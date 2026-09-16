rule sig_20160526_57632ea9d344bf98bd9797c2179478ce {
  meta:
    description = "datamaliciousorder - file 20160526_57632ea9d344bf98bd9797c2179478ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ed8bf33bf8ef54340393695787bc4986f331beca00189cd77e355a3101a697f"

  strings:
    $s1  = "Og);else if (VvBEOEwBXWiQOxb == (503 + Math.round((Math.pow(Math.sin(802), 2) + Math.pow(Math.cos(802), 2) - 1))-439)) Coggz += " ascii
    $s2  = "nd((Math.pow(Math.sin(400), 2) + Math.pow(Math.cos(400), 2) - 1))-394) & 0xff;uhUqxSrNnMApySmTQ = wGBAMbXLYMulFNdX>> (509 + Math" ascii
    $s3  = "function tfizgitkSYZJW(DcCwqhGsttyvU) {var LTvxrZkAkiuDrUJB = DSVDqSpdEzycaajKYSweAF.join(MSkaojW[0]);var VVQQfHQvowIpOg, uhUqxS" ascii
    $s4  = "function EQFwsmr(arPaA,sDmzAoaMDwVugBNUIdIZDhYk){return arPaA.charAt(sDmzAoaMDwVugBNUIdIZDhYk);}" fullword ascii
    $s5  = "rIkfVgNzeFMVJTnKUP(VVQQfHQvowIpOg, uhUqxSrNnMApySmTQ);else Coggz += xYklqHhoYkMFVJ(VVQQfHQvowIpOg, uhUqxSrNnMApySmTQ, fapPOyZqZj" ascii
    $s6  = "LSVl);} while (YJmbxDIGIiDsmgIoEg < DcCwqhGsttyvU.length);return Coggz;}" fullword ascii
    $s7  = "function xYklqHhoYkMFVJ(uazVpiOTfGBrm,EqPrJIaXTZbyE,HtCKvQDmEeDcSkSY){return String.fromCharCode(uazVpiOTfGBrm,EqPrJIaXTZbyE,HtC" ascii
    $s8  = "function xYklqHhoYkMFVJ(uazVpiOTfGBrm,EqPrJIaXTZbyE,HtCKvQDmEeDcSkSY){return String.fromCharCode(uazVpiOTfGBrm,EqPrJIaXTZbyE,HtC" ascii
    $s9  = "function jdzbTVs(rMRDoSYGzlLwfagw,VmtXo){return rMRDoSYGzlLwfagw.indexOf(VmtXo);}" fullword ascii
    $s10 = "function rIkfVgNzeFMVJTnKUP(jrIoeferUshNpqZZroyzKoLG,sVSJrppcHrJlqblQkHNkvNm){return String.fromCharCode(jrIoeferUshNpqZZroyzKoL" ascii
    $s11 = "function EA(uQUnYxrhkcMebKOlXRq){return String.fromCharCode(uQUnYxrhkcMebKOlXRq);}" fullword ascii
    $s12 = "function rIkfVgNzeFMVJTnKUP(jrIoeferUshNpqZZroyzKoLG,sVSJrppcHrJlqblQkHNkvNm){return String.fromCharCode(jrIoeferUshNpqZZroyzKoL" ascii
    $s13 = "function tfizgitkSYZJW(DcCwqhGsttyvU) {var LTvxrZkAkiuDrUJB = DSVDqSpdEzycaajKYSweAF.join(MSkaojW[0]);var VVQQfHQvowIpOg, uhUqxS" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}