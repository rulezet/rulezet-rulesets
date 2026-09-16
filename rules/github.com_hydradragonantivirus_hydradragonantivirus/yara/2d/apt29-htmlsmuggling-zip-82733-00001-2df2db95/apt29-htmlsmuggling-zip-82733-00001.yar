rule APT29_HTMLSmuggling_ZIP_82733_00001 {
  meta:
    author      = "Cluster25"
    description = "Rule to detect the EnvyScout HTML smuggling with ZIP payload used in the APT29/Nobelium APT29 chain"
    date        = "2022-05-12"
    hash        = "d5c84cbd7dc70e71f3eb24434a58b2f149d0c39faa7e4157552b60c7dbb53d11"
    report      = "https://blog.cluster25.duskrise.com/2022/05/13/cozy-smuggled-into-the-box"

  strings:
    $s1 = "new Blob("
    $s2 = "new Uint8Array("
    $s3 = "application/octet-stream"
    $t1 = "saveAs("
    $t2 = "download("
    $r1 = "for(var i = 0x0; i < d['length']; i++) {\n    d[i] = d[i]"

  condition:
    (filesize > 500KB and all of ($s*) and ($t1 or $t2) and $r1)
}