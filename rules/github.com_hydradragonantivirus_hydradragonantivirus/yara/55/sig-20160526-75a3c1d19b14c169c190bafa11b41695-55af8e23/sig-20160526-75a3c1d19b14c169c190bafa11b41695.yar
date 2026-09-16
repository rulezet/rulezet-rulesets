rule sig_20160526_75a3c1d19b14c169c190bafa11b41695 {
  meta:
    description = "datamaliciousorder - file 20160526_75a3c1d19b14c169c190bafa11b41695.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49773b33fa96155006df2ad4000520df131cbd89b18c0aafd8169010aa49ea92"

  strings:
    $s1  = "function nHxrM(DRHHgMVipUuhU) {var XrndvrQPX = AchldHUA.join(bbPtltba[0]);var nTVikHbBQmZRfpwAOvn, ZoaDQjWkjqYix, TFMoZVDCeWQgXc" ascii
    $s2  = "pow(Math.sin(575), 2) + Math.pow(Math.cos(575), 2) - 1))-121)) UIUjFRPUo += xr(nTVikHbBQmZRfpwAOvn);else if (ymzjGdAhPHgn == (49" ascii
    $s3  = "), 2) - 1))-460) & 0xff;TFMoZVDCeWQgXcHjop = tiyTKtopdzQpzNOfdeb & 0xff;if (tBenUaWdjufdKIkcqRXLXTfa == (185 + Math.round((Math." ascii
    $s4  = "function dPjUhxHmcO(qaERmhyJfbnkponuJb,jLIsfSyoLXlwRs){return qaERmhyJfbnkponuJb.charAt(jLIsfSyoLXlwRs);}" fullword ascii
    $s5  = "< DRHHgMVipUuhU.length);return UIUjFRPUo;}" fullword ascii
    $s6  = "function QRGhVvDL(JLaNEzaIpHQoBrlULUlG,GcuLmgRoB,mKSYKdxCyXifwGa){return String.fromCharCode(JLaNEzaIpHQoBrlULUlG,GcuLmgRoB,mKSY" ascii
    $s7  = "oaDQjWkjqYix);else UIUjFRPUo += QRGhVvDL(nTVikHbBQmZRfpwAOvn, ZoaDQjWkjqYix, TFMoZVDCeWQgXcHjop);} while (DYQgebGIPVzNSptCvuvpE " ascii
    $s8  = "function nHxrM(DRHHgMVipUuhU) {var XrndvrQPX = AchldHUA.join(bbPtltba[0]);var nTVikHbBQmZRfpwAOvn, ZoaDQjWkjqYix, TFMoZVDCeWQgXc" ascii
    $s9  = "function oKFMIJsdTo(OWNlWZrfPXepW,ITtfURUqhrQFotOWSNu){return String.fromCharCode(OWNlWZrfPXepW,ITtfURUqhrQFotOWSNu);}" fullword ascii
    $s10 = "function KpIiOEExHaqxZLzMrHq(UHnZQmczymDcQRVZ,DVgqumYkLWDJDdPl){return UHnZQmczymDcQRVZ.indexOf(DVgqumYkLWDJDdPl);}" fullword ascii
    $s11 = "function QRGhVvDL(JLaNEzaIpHQoBrlULUlG,GcuLmgRoB,mKSYKdxCyXifwGa){return String.fromCharCode(JLaNEzaIpHQoBrlULUlG,GcuLmgRoB,mKSY" ascii
    $s12 = "function xr(SDOVuOrhoRI){return String.fromCharCode(SDOVuOrhoRI);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}