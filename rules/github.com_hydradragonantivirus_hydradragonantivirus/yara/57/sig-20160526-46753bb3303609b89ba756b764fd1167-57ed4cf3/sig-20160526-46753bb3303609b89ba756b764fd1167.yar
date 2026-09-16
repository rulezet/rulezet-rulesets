rule sig_20160526_46753bb3303609b89ba756b764fd1167 {
  meta:
    description = "datamaliciousorder - file 20160526_46753bb3303609b89ba756b764fd1167.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b1e5ac916dc34f75f159aff5c67fa004b3463f5302b64688dd27386eb4802d0a"

  strings:
    $s1  = "HLqEuCSHcJdAoiJ);else if (dezeVILQoJvjoCSRVSf == (357 + Math.round((Math.pow(Math.sin(658), 2) + Math.pow(Math.cos(658), 2) - 1)" ascii
    $s2  = "ath.sin(876), 2) + Math.pow(Math.cos(876), 2) - 1))-938) | cVOsn<< (622 + Math.round((Math.pow(Math.sin(373), 2) + Math.pow(Math" ascii
    $s3  = "function FdbAvKbKM(TBqXzzdpkWLfd) {var GnMuurPwXPmsqtvuOnYSiCa = iNAyaF.join(stdKmk[0]);var lDGGwmkxHLqEuCSHcJdAoiJ, KquYhDUXiYj" ascii
    $s4  = "function wXXqHQwTzchXVRf(QgIpdBAjQql,FPaGvaejMorJAXiwfgwwGFt){return QgIpdBAjQql.charAt(FPaGvaejMorJAXiwfgwwGFt);}" fullword ascii
    $s5  = "PeeL, yYJhtihYWlvdwoCmysxRoZTY, retvhJwQFhexF, RMLjtaoIyjBFG, cVOsn, dezeVILQoJvjoCSRVSf, BZnrZdfHCYszULsTBAszSD, lwoeSJJWPdHEdN" ascii
    $s6  = "cOCuhlsx(lDGGwmkxHLqEuCSHcJdAoiJ, KquYhDUXiYjPeeL, yYJhtihYWlvdwoCmysxRoZTY);} while (lwoeSJJWPdHEdNwAmP < TBqXzzdpkWLfd.length)" ascii
    $s7  = "function yujHJBZwBZABWkffHYIlUG(LRhcRMrUGTdsKqfAk,kfsbIQHzaTbGThn){return String.fromCharCode(LRhcRMrUGTdsKqfAk,kfsbIQHzaTbGThn)" ascii
    $s8  = "function qsDxjRGJzkHpRD(UUEXueTEyTZonPFAmEJEZiHN,RJFVmYbECZZklNmwWEd){return UUEXueTEyTZonPFAmEJEZiHN.indexOf(RJFVmYbECZZklNmwWE" ascii
    $s9  = "function Cn(oteEvvxmWwLjX){return String.fromCharCode(oteEvvxmWwLjX);}" fullword ascii
    $s10 = "function qsDxjRGJzkHpRD(UUEXueTEyTZonPFAmEJEZiHN,RJFVmYbECZZklNmwWEd){return UUEXueTEyTZonPFAmEJEZiHN.indexOf(RJFVmYbECZZklNmwWE" ascii
    $s11 = "function pnggTqQlXSDbtypFcOCuhlsx(yJbEgNoHT,nyMWkx,IjQwGHYTpEXNPxdAcTHsHIU){return String.fromCharCode(yJbEgNoHT,nyMWkx,IjQwGHYT" ascii
    $s12 = "function pnggTqQlXSDbtypFcOCuhlsx(yJbEgNoHT,nyMWkx,IjQwGHYTpEXNPxdAcTHsHIU){return String.fromCharCode(yJbEgNoHT,nyMWkx,IjQwGHYT" ascii
    $s13 = "function yujHJBZwBZABWkffHYIlUG(LRhcRMrUGTdsKqfAk,kfsbIQHzaTbGThn){return String.fromCharCode(LRhcRMrUGTdsKqfAk,kfsbIQHzaTbGThn)" ascii
    $s14 = ")-293)) QrRnxoKcaPbWJ += yujHJBZwBZABWkffHYIlUG(lDGGwmkxHLqEuCSHcJdAoiJ, KquYhDUXiYjPeeL);else QrRnxoKcaPbWJ += pnggTqQlXSDbtypF" ascii
    $s15 = ";return QrRnxoKcaPbWJ;}" fullword ascii
    $s16 = "function FdbAvKbKM(TBqXzzdpkWLfd) {var GnMuurPwXPmsqtvuOnYSiCa = iNAyaF.join(stdKmk[0]);var lDGGwmkxHLqEuCSHcJdAoiJ, KquYhDUXiYj" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}