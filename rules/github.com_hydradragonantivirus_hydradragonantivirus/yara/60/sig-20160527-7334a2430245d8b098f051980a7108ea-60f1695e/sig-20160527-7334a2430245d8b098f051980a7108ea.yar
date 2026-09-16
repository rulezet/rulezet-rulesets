rule sig_20160527_7334a2430245d8b098f051980a7108ea {
  meta:
    description = "datamaliciousorder - file 20160527_7334a2430245d8b098f051980a7108ea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "995319ecf9e5f60688fb60752bb91f6bf8875bc5760a30ba3aad50c8b7a48e70"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<al43iRzE.length;i++)if(i%2==0)x.push(al43iRzE[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}