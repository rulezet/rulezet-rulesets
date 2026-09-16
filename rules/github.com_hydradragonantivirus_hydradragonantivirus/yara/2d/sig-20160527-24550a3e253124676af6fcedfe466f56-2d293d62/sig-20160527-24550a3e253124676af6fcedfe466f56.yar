rule sig_20160527_24550a3e253124676af6fcedfe466f56 {
  meta:
    description = "datamaliciousorder - file 20160527_24550a3e253124676af6fcedfe466f56.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f4b865a96e09d425a48a7881319856462000611305f62db6f32be9883780026"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<al7srYllt.length;i++)if(i%2==0)x.push(al7srYllt[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}