rule sig_20160527_2f031cb6450b9986265a3ade2b031045 {
  meta:
    description = "datamaliciousorder - file 20160527_2f031cb6450b9986265a3ade2b031045.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e588e3bb3e154790ed7568d095e9e22fafe1b614bb675f1f69e55ba30bc051ae"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<abB9CLiF.length;i++)if(i%2==0)x.push(abB9CLiF[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}