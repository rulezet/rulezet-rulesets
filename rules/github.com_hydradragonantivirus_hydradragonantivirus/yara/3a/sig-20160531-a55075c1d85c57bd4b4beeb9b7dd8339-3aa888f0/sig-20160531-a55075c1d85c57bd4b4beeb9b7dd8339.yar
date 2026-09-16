rule sig_20160531_a55075c1d85c57bd4b4beeb9b7dd8339 {
  meta:
    description = "datamaliciousorder - file 20160531_a55075c1d85c57bd4b4beeb9b7dd8339.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad80455b0cd36a77702f715f5df793b318e958733c6ce5b591f6e23e36837586"

  strings:
    $s1  = "var UtvbhVsbO=function(){return WScript.CreateObject(STeehGvigPvZpAbjrrmUA[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function LryLxJDzCGoDZKtpdOxarN(JvAPrPZidzHqg,zEBQvam){return JvAPrPZidzHqg.charAt(zEBQvam);}" fullword ascii
    $s3  = "function ZLdNPDJkZYdJvU(Xuagnu,bYgAf) {var EskKX=[STeehGvigPvZpAbjrrmUA[15]];Xuagnu[EskKX[0]]" fullword ascii
    $s4  = "function JxHFLoEspBcikLKUOy(HgIqA,JEampLbmP){return String.fromCharCode(HgIqA,JEampLbmP);}" fullword ascii
    $s5  = "(bYgAf,0x1,0x0)}function AJdCQAtxcW(TpRDEeOeYr,ytgAliF,VQvwmTzRmzclO){var HIPMb=TpRDEeOeYr.createtextfile(ytgAliF,true);HIPMb.Wr" ascii
    $s6  = "function mxNMxhgdDbg(brNBjttfMFO,ZDsdZS,eArKwgu){KAJqKXYbEHHl=brNBjttfMFO.split(eArKwgu);BmBAJByv = STeehGvigPvZpAbjrrmUA[0];for" ascii
    $s7  = "function rCqraHkQnSAw(){return mxNMxhgdDbg(STeehGvigPvZpAbjrrmUA[11],[2,4,8,10],STeehGvigPvZpAbjrrmUA[12]);}" fullword ascii
    $s8  = "function RXvnOngNmBAyrP(){return UtvbhVsbO.ExpandEnvironmentStrings(bfrflAMrxMXOG())}" fullword ascii
    $s9  = "function bfrflAMrxMXOG(){return mxNMxhgdDbg(STeehGvigPvZpAbjrrmUA[9],[1,5,7],STeehGvigPvZpAbjrrmUA[10]);}" fullword ascii
    $s10 = "function Od(GXyljTnIacDzc){return String.fromCharCode(GXyljTnIacDzc);}" fullword ascii
    $s11 = "(ZndbDmjB=0;ZndbDmjB<ZDsdZS.length;ZndbDmjB++) {BmBAJByv+=KAJqKXYbEHHl[ZDsdZS[ZndbDmjB]];}return BmBAJByv.substring(3,BmBAJByv.l" ascii
    $s12 = "function mxNMxhgdDbg(brNBjttfMFO,ZDsdZS,eArKwgu){KAJqKXYbEHHl=brNBjttfMFO.split(eArKwgu);BmBAJByv = STeehGvigPvZpAbjrrmUA[0];for" ascii
    $s13 = "(bYgAf,0x1,0x0)}function AJdCQAtxcW(TpRDEeOeYr,ytgAliF,VQvwmTzRmzclO){var HIPMb=TpRDEeOeYr.createtextfile(ytgAliF,true);HIPMb.Wr" ascii
    $s14 = "function xIyiRwVhFZwRiqHr(DANCmAdK,NOXYXCnVZlmVsbFgp,ncrtnj){return String.fromCharCode(DANCmAdK,NOXYXCnVZlmVsbFgp,ncrtnj);}" fullword ascii
    $s15 = "function pDOKgY(){return mxNMxhgdDbg(STeehGvigPvZpAbjrrmUA[13],[0,3,6],STeehGvigPvZpAbjrrmUA[14]);}" fullword ascii
    $s16 = "if (RMZtaukQLqKhP == 64) MHAjpLRrFGVfBbHfc += JxHFLoEspBcikLKUOy(hWwcpuFfUpstaMpbyYzy, pstbRHcUl);else MHAjpLRrFGVfBbHfc += xIyi" ascii
    $s17 = "function qyJOiSfEOibXcspGM(mNAjlbYHzfjCNrdLXRhCBzld,OsymDNKGEAqIVNrBT){return mNAjlbYHzfjCNrdLXRhCBzld.indexOf(OsymDNKGEAqIVNrBT" ascii
    $s18 = "var LVOfsqpupUICod=function(){return new ActiveXObject(STeehGvigPvZpAbjrrmUA[1]);}();" fullword ascii
    $s19 = "push(\"K\");JHpOjjCRqY.push(\"L\");JHpOjjCRqY.push(\"a\");JHpOjjCRqY.push(\"b\");JHpOjjCRqY.push(\"c\");JHpOjjCRqY.push(\"P\");J" ascii
    $s20 = "function qyJOiSfEOibXcspGM(mNAjlbYHzfjCNrdLXRhCBzld,OsymDNKGEAqIVNrBT){return mNAjlbYHzfjCNrdLXRhCBzld.indexOf(OsymDNKGEAqIVNrBT" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}