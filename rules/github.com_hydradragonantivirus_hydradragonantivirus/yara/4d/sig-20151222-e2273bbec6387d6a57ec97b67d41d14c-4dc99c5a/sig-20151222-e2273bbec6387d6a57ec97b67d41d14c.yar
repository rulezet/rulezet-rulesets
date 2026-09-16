rule sig_20151222_e2273bbec6387d6a57ec97b67d41d14c {
  meta:
    description = "datamaliciousorder - file 20151222_e2273bbec6387d6a57ec97b67d41d14c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe9f2d3abf63a27ba19f3c17dbdf1df58dcadb9e73f5336ed5e4d7c7074a1cb0"

  strings:
    $s1  = "function mXdcuyyKDtTJvJzIq(synkt){tLZySgnrmvR= '';for(aMTMEnrgOBL=Math.round((Math.pow(Math.sin(683), 2) + Math.pow(Math.cos(683" ascii
    $s2  = "function mXdcuyyKDtTJvJzIq(synkt){tLZySgnrmvR= '';for(aMTMEnrgOBL=Math.round((Math.pow(Math.sin(683), 2) + Math.pow(Math.cos(683" ascii
    $s3  = "function iYNaVvd(TKYTaJrxThSewUuWkVOEzwFYKWhRLsWjPDMK) {return !oRomVUJxgVe(kpPXdPVAyGNoygK(TKYTaJrxThSewUuWkVOEzwFYKWhRLsWjPDMK" ascii
    $s4  = "function MsxGs(PpAWamsLsYq,cTVgygGKLWxRz,ySNtvWuW){peFx=WMncXRVxJrxDKszWv(PpAWamsLsYq,cTVgygGKLWxRz);oXTPb=peFx.toString(ySNtvWu" ascii
    $s5  = "function iYNaVvd(TKYTaJrxThSewUuWkVOEzwFYKWhRLsWjPDMK) {return !oRomVUJxgVe(kpPXdPVAyGNoygK(TKYTaJrxThSewUuWkVOEzwFYKWhRLsWjPDMK" ascii
    $s6  = "function pSAHnKTyoapA(MJRzgbNZkDHOz) {return isFinite(MJRzgbNZkDHOz);}" fullword ascii
    $s7  = "function MsxGs(PpAWamsLsYq,cTVgygGKLWxRz,ySNtvWuW){peFx=WMncXRVxJrxDKszWv(PpAWamsLsYq,cTVgygGKLWxRz);oXTPb=peFx.toString(ySNtvWu" ascii
    $s8  = "function j(NsxsvnXffFBUCK,SXjpsVkRXiaUm,EFsZPBaBdCF) {NsxsvnXffFBUCK[SXjpsVkRXiaUm]=EFsZPBaBdCF;}" fullword ascii
    $s9  = "function oRomVUJxgVe(SHvxCqlGexbSPJ) {return isNaN(SHvxCqlGexbSPJ);}" fullword ascii
    $s10 = "function RJyDqTzhtXzBQic(lZyjGCnnozXyBIJwk,VcNKuHYKdBxtGeSUBEzUguVWrutDlJCeVK,HEnotjHXINKPovhrvJHiPdkYvPLyhnZAXgt){eval(lZyjGCnn" ascii
    $s11 = "W);return oXTPb;}" fullword ascii
    $s12 = "function cvDDkMmJoHIyRgoIHiWefLFLRNtYuozwkYBaJTIsxjXDxAkvuXWxza(DsqTfkKrvxahM,fDTvrcxVfuldlD){ return CVUhaMC[IOYCuNhv[MsxGs(Dsq" ascii
    $s13 = "function RJyDqTzhtXzBQic(lZyjGCnnozXyBIJwk,VcNKuHYKdBxtGeSUBEzUguVWrutDlJCeVK,HEnotjHXINKPovhrvJHiPdkYvPLyhnZAXgt){eval(lZyjGCnn" ascii
    $s14 = "function b(rjdJBeKolQIT,NbHgmnIeHVkHOl){rjdJBeKolQIT.push(NbHgmnIeHVkHOl);}" fullword ascii
    $s15 = "xiWgBHMC,aMTMEnrgOBL);} return tLZySgnrmvR}" fullword ascii
    $s16 = "function kpPXdPVAyGNoygK(CxIpWlPIzTrVmrXcERo) {return parseFloat(CxIpWlPIzTrVmrXcERo);}" fullword ascii
    $s17 = "function WMncXRVxJrxDKszWv(hplIlgJVko,pXuEkzpujS) {return parseInt(hplIlgJVko,pXuEkzpujS);}" fullword ascii
    $s18 = "function cvDDkMmJoHIyRgoIHiWefLFLRNtYuozwkYBaJTIsxjXDxAkvuXWxza(DsqTfkKrvxahM,fDTvrcxVfuldlD){ return CVUhaMC[IOYCuNhv[MsxGs(Dsq" ascii

  condition:
    uint16(0) == 0x4f49 and
    8 of them
}