rule sig_20160526_558a955bdcc09ebd60604be75e833aec {
  meta:
    description = "datamaliciousorder - file 20160526_558a955bdcc09ebd60604be75e833aec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "45f530c0cb07e25f73f62aec66e28f4abb52c9f8e388437a6d4a8708a937bf98"

  strings:
    $s1  = "function GbBJfZR(HGwgtHGSVOMCP) {var gnQdqLCNU = dryKqbDXLUrzmZORC.join(oylaJBUXNCptq[0]);var ytRrsjas, jzjSnEqSmCPRgtiSoExt, AS" ascii
    $s2  = "(Math.cos(452), 2) - 1))-522)) qIhswbcXCbbWGjNTvsUdb += rHlknoOinQZAJ(ytRrsjas, jzjSnEqSmCPRgtiSoExt);else qIhswbcXCbbWGjNTvsUdb" ascii
    $s3  = "swbcXCbbWGjNTvsUdb += xZ(ytRrsjas);else if (riDTmYzkCwevQLAMGkCOyuWV == (586 + Math.round((Math.pow(Math.sin(452), 2) + Math.pow" ascii
    $s4  = "function tllrT(CfBFJxHTdFbrI,wKlMzQrBx){return CfBFJxHTdFbrI.charAt(wKlMzQrBx);}" fullword ascii
    $s5  = "function GbBJfZR(HGwgtHGSVOMCP) {var gnQdqLCNU = dryKqbDXLUrzmZORC.join(oylaJBUXNCptq[0]);var ytRrsjas, jzjSnEqSmCPRgtiSoExt, AS" ascii
    $s6  = "function IUNIlNWLSOqpXlKOx(GBXDoktocNZkXPnQFqkn,cOnPFeuUJEDWuWW){return GBXDoktocNZkXPnQFqkn.indexOf(cOnPFeuUJEDWuWW);}" fullword ascii
    $s7  = "function rHlknoOinQZAJ(RGAqqbBNn,VHjAuqdiMxEJVfRVij){return String.fromCharCode(RGAqqbBNn,VHjAuqdiMxEJVfRVij);}" fullword ascii
    $s8  = "function OLkdsnMw(URXjnyigCqtkmvomi,NgEMRdZwgSi,FRALwQHizvLHeiJ){return String.fromCharCode(URXjnyigCqtkmvomi,NgEMRdZwgSi,FRALwQ" ascii
    $s9  = "function OLkdsnMw(URXjnyigCqtkmvomi,NgEMRdZwgSi,FRALwQHizvLHeiJ){return String.fromCharCode(URXjnyigCqtkmvomi,NgEMRdZwgSi,FRALwQ" ascii
    $s10 = " += OLkdsnMw(ytRrsjas, jzjSnEqSmCPRgtiSoExt, ASWXf);} while (NkcTJjvmAZMhiqRfqssPua < HGwgtHGSVOMCP.length);return qIhswbcXCbbWG" ascii
    $s11 = "function xZ(FPsYMzfNJ){return String.fromCharCode(FPsYMzfNJ);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}