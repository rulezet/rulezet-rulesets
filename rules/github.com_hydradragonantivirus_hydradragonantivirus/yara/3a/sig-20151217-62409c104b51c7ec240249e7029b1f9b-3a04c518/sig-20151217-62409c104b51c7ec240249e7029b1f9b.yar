rule sig_20151217_62409c104b51c7ec240249e7029b1f9b {
  meta:
    description = "datamaliciousorder - file 20151217_62409c104b51c7ec240249e7029b1f9b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dde710ed0e8c2e015359738d098dc46acedf1595e4fd85a5ae3da430342ba281"

  strings:
    $s1  = "function XESqdyVeRPHQDYodG(dvOzJ){dGCTYUKhECN= '';KFwTGsirJVO=Math.round((Math.pow(Math.sin(331), 2) + Math.pow(Math.cos(331), 2" ascii
    $s2  = ") - 1));while(true){if (KFwTGsirJVO >= (1144+656)/300){break;}dTDJDIZxn[KFwTGsirJVO]=Math.round((Math.pow(Math.sin(880), 2) + Ma" ascii
    $s3  = "th.pow(Math.cos(880), 2) - 1)); while(true) { if(dTDJDIZxn[KFwTGsirJVO] > dvOzJ[KFwTGsirJVO].length-(479+55)/534) { break; } if " ascii
    $s4  = "w(Math.cos(916), 2) - 1)));} dTDJDIZxn[KFwTGsirJVO]++;}KFwTGsirJVO++;} return dGCTYUKhECN}" fullword ascii
    $s5  = "function XESqdyVeRPHQDYodG(dvOzJ){dGCTYUKhECN= '';KFwTGsirJVO=Math.round((Math.pow(Math.sin(331), 2) + Math.pow(Math.cos(331), 2" ascii
    $s6  = "function zhodIUh(nYSLmaYSeYgNXGCzKBgXqUauyNVGmwfxYFaV) {return !hlLvPmOmWXy(oUJnbeEScZXifqI(nYSLmaYSeYgNXGCzKBgXqUauyNVGmwfxYFaV" ascii
    $s7  = "var u = new Array();u[0]=[];u[0][0]='d';u[0][1]='a';u[0][2]='d';u[0][3]='a';u[0][4]='46';u[0][5]='3d';u[0][6]='42';u[0][7]='14';" ascii
    $s8  = "function SjfAhwxgAcvFDxSgpZTzLZPQyKlAoompoYaILAzliBnBbLbAFMJxTV(kefEORVZJLdhC,RoUimPlILkBxEU){ return XHVvZjd[QSUsTXOV[cZKir(kef" ascii
    $s9  = "I);return xZJoS;}" fullword ascii
    $s10 = "function cZKir(lhCBJYooXag,hStZJEVJnAuCT,MlgmTvmI){qnMp=YxwvfnvOUyulInIGn(lhCBJYooXag,hStZJEVJnAuCT);xZJoS=qnMp.toString(MlgmTvm" ascii
    $s11 = "function Y(losDEiWDzJCI,oDfSHgaQyYYzAj){losDEiWDzJCI.push(oDfSHgaQyYYzAj);}" fullword ascii
    $s12 = "function hlLvPmOmWXy(SOmuCVbfbBLWdn) {return isNaN(SOmuCVbfbBLWdn);}" fullword ascii
    $s13 = "function oUJnbeEScZXifqI(oFcoZBvQcgNGDUjtaOz) {return parseFloat(oFcoZBvQcgNGDUjtaOz);}" fullword ascii
    $s14 = "function SjfAhwxgAcvFDxSgpZTzLZPQyKlAoompoYaILAzliBnBbLbAFMJxTV(kefEORVZJLdhC,RoUimPlILkBxEU){ return XHVvZjd[QSUsTXOV[cZKir(kef" ascii
    $s15 = "function HLhzswhBTHGV(TkszLgMZGEUDP) {return isFinite(TkszLgMZGEUDP);}" fullword ascii
    $s16 = "function zhodIUh(nYSLmaYSeYgNXGCzKBgXqUauyNVGmwfxYFaV) {return !hlLvPmOmWXy(oUJnbeEScZXifqI(nYSLmaYSeYgNXGCzKBgXqUauyNVGmwfxYFaV" ascii
    $s17 = "function s(iFCTSOQCOwjQBA,MoMsXoGvIzrwv,PUsLJllnhQu) {iFCTSOQCOwjQBA[MoMsXoGvIzrwv]=PUsLJllnhQu;}" fullword ascii
    $s18 = "function IJdzhruHWlAXzvs(fHBxcMGOwZwIcLDhQ,PynCzsgWJQCNBylMpUgFlvLxbdxPyRtErS,zSoXStXpEGAreMcmNrfIgLfpSzldxGxnTHz){eval(fHBxcMGO" ascii
    $s19 = "function IJdzhruHWlAXzvs(fHBxcMGOwZwIcLDhQ,PynCzsgWJQCNBylMpUgFlvLxbdxPyRtErS,zSoXStXpEGAreMcmNrfIgLfpSzldxGxnTHz){eval(fHBxcMGO" ascii
    $s20 = "function cZKir(lhCBJYooXag,hStZJEVJnAuCT,MlgmTvmI){qnMp=YxwvfnvOUyulInIGn(lhCBJYooXag,hStZJEVJnAuCT);xZJoS=qnMp.toString(MlgmTvm" ascii

  condition:
    uint16(0) == 0x5351 and
    8 of them
}