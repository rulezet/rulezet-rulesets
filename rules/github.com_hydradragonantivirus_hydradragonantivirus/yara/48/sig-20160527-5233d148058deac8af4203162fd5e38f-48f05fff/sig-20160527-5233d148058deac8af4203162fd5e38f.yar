rule sig_20160527_5233d148058deac8af4203162fd5e38f {
  meta:
    description = "datamaliciousorder - file 20160527_5233d148058deac8af4203162fd5e38f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6a54344580b721e603a088a193dc86936c9064b0b7efcadb529281231238113"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a304cLP.length;i++)if(i%2==0)x.push(a304cLP[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}