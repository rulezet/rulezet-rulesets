rule sig_20160526_e68edb88b2f15cd52c479b097d1517e6 {
  meta:
    description = "datamaliciousorder - file 20160526_e68edb88b2f15cd52c479b097d1517e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "67d05ed523cb1da25939fbe8c202cf87089d4b8845744986d74bd94e39c98342"

  strings:
    $s1  = "ZsagwMky += Or(rKXebkFVRDd);else if (DvpVbYHOXPJ == (181 + Math.round((Math.pow(Math.sin(198), 2) + Math.pow(Math.cos(198), 2) -" ascii
    $s2  = "function rpsPmne(GBfRIEUDSqtJg) {var wTlxMrqDeebYhKlNkYMbqmn = hvIzlzJEJGq.join(jDbJBC[0]);var rKXebkFVRDd, luHuFUF, EWYFSjXlMB," ascii
    $s3  = "function CFKNYd(UrXOmEuUNoAfWh,zWvmzvZPwCApqlsGmq){return UrXOmEuUNoAfWh.charAt(zWvmzvZPwCApqlsGmq);}" fullword ascii
    $s4  = "ile (RXOuQieuKegGCtUlBfGDBawA < GBfRIEUDSqtJg.length);return eZsagwMky;}" fullword ascii
    $s5  = "function prpgxrBOeIF(tDzGv,qTXnUjvYVWFp,rdkxfnZOZhi){return String.fromCharCode(tDzGv,qTXnUjvYVWFp,rdkxfnZOZhi);}" fullword ascii
    $s6  = "function Or(sPLhozPCSBjK){return String.fromCharCode(sPLhozPCSBjK);}" fullword ascii
    $s7  = "function CuTFJYdUGSBObXcHWJ(LfxVjtvsDwuCNKRzrXRhhy,UsrgdnxsU){return LfxVjtvsDwuCNKRzrXRhhy.indexOf(UsrgdnxsU);}" fullword ascii
    $s8  = " 1))-117)) eZsagwMky += MvUtlYHUuudFj(rKXebkFVRDd, luHuFUF);else eZsagwMky += prpgxrBOeIF(rKXebkFVRDd, luHuFUF, EWYFSjXlMB);} wh" ascii
    $s9  = "function rpsPmne(GBfRIEUDSqtJg) {var wTlxMrqDeebYhKlNkYMbqmn = hvIzlzJEJGq.join(jDbJBC[0]);var rKXebkFVRDd, luHuFUF, EWYFSjXlMB," ascii
    $s10 = "function MvUtlYHUuudFj(slEjmHCxij,MkdzvXBqnDSxxcAv){return String.fromCharCode(slEjmHCxij,MkdzvXBqnDSxxcAv);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}