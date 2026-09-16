rule sig_20160523_b2d1db260dfaa3cf1295e3f4147de1f0 {
  meta:
    description = "datamaliciousorder - file 20160523_b2d1db260dfaa3cf1295e3f4147de1f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "553884479a2228ad2f391260302a238dbe57534d3775d2064051e39dea0687ac"

  strings:
    $s1  = "function wmxyekHjGD(dWRbgAVJ,TibDZfFYwshf) {dWRbgAVJ.Run(TibDZfFYwshf, 0x1, 0x0);}" fullword ascii
    $s2  = "function giOsPdIEGN() {return/*WZwcIMlNzZaiezpKLtJvytyaBbbfBhSlJWImlwZmJqrPxIpashSwxVlYaFwaKdZSiPRCFaYCcsZbGVKgBDtzjNBSVkXlgSQBd" ascii
    $s3  = "function yjVxpkfd(UGpAy) {var xxrpxKxp=LRfFAkwKSgqIzbq[13];for(var zxpIR=0;zxpIR<UGpAy;zxpIR++){vxjlP+=xxrpxKxp.charAt(Math.floo" ascii
    $s4  = "function yjVxpkfd(UGpAy) {var xxrpxKxp=LRfFAkwKSgqIzbq[13];for(var zxpIR=0;zxpIR<UGpAy;zxpIR++){vxjlP+=xxrpxKxp.charAt(Math.floo" ascii
    $s5  = "fqJCKw.length;eAsvklYL++) {SEYVKfm+=sEUzd[fqJCKw[eAsvklYL]];}return SEYVKfm.substring(3,SEYVKfm.length);}" fullword ascii
    $s6  = "function HKOXtuHGLpIGl() {giOsPdIEGN().Sleep(2484001-533);}" fullword ascii
    $s7  = "function FBhnk(lPlOvTRc,fqJCKw,WVpzNvhRS){sEUzd=lPlOvTRc.split(WVpzNvhRS);SEYVKfm = LRfFAkwKSgqIzbq[12];for(eAsvklYL=0;eAsvklYL<" ascii
    $s8  = "function SJzGH(qQxzXamo,TlDfO,zVglfycpfe){IrPU(qQxzXamo);FlrfdZAv(qQxzXamo);ToUbNDH(qQxzXamo,TlDfO);GXWusweHi(qQxzXamo);tWKe(qQx" ascii
    $s9  = "function eLZBJR(FLVaIG){return FLVaIG.ExpandEnvironmentStrings(LRfFAkwKSgqIzbq[9])}" fullword ascii
    $s10 = "function xXJDX(FLVaIG){return new ActiveXObject(FLVaIG);}" fullword ascii
    $s11 = "function FBhnk(lPlOvTRc,fqJCKw,WVpzNvhRS){sEUzd=lPlOvTRc.split(WVpzNvhRS);SEYVKfm = LRfFAkwKSgqIzbq[12];for(eAsvklYL=0;eAsvklYL<" ascii
    $s12 = "function GXWusweHi(bEBxqs) {var dczeLGVZDj=[];bEBxqs.position=dczeLGVZDj.length*(9077240-253);}" fullword ascii
    $s13 = "function OMMQ(FPoJgg,imJYUqw){XuBy = LRfFAkwKSgqIzbq[10].split(LRfFAkwKSgqIzbq[11]);imJYUqw.open(XuBy[0]+XuBy[2]+XuBy[3], FPoJgg" ascii
    $s14 = "function ToUbNDH(LuFg,qDKam) {LuFg.write(qDKam);}" fullword ascii
    $s15 = "function LqPIxwv(mpske) {mpske.close();}" fullword ascii
    $s16 = "function FlrfdZAv(XxvoIapJK) {XxvoIapJK.type=1;}" fullword ascii
    $s17 = "r(Math.random()*xxrpxKxp.length));}return vxjlP;}" fullword ascii
    $s18 = "function SJzGH(qQxzXamo,TlDfO,zVglfycpfe){IrPU(qQxzXamo);FlrfdZAv(qQxzXamo);ToUbNDH(qQxzXamo,TlDfO);GXWusweHi(qQxzXamo);tWKe(qQx" ascii
    $s19 = "function JYMYNOP(){return Math.random();}" fullword ascii
    $s20 = "if(hnOM>GWBBq.length) break;" fullword ascii

  condition:
    uint16(0) == 0x1427 and
    8 of them
}