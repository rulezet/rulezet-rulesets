rule sig_20160527_5732a27461bcebd059113e588c940dee {
  meta:
    description = "datamaliciousorder - file 20160527_5732a27461bcebd059113e588c940dee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "354f986418527e5cd6093d0c178081c3c83a05e38fe5c390b40b82b38a36ee26"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<abFqLZV.length;i++)if(i%2==0)x.push(abFqLZV[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}