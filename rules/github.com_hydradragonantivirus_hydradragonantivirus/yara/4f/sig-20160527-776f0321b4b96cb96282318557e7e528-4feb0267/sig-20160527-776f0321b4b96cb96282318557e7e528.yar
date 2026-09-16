rule sig_20160527_776f0321b4b96cb96282318557e7e528 {
  meta:
    description = "datamaliciousorder - file 20160527_776f0321b4b96cb96282318557e7e528.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85ccaacd8852f6bcc1797162a60562b4e9c3fd361d6554d1e18180d72a699f99"

  strings:
    $s1  = "function skTxpCcWSnA() {return WScript;}function QyupLsnpdNEUIK(){return VanDqXDdCZc.ExpandEnvironmentStrings(ydPZhGQZs())}" fullword ascii
    $s2  = "function WzKztEcqom(MKbdoeMgnPodn) {var LrQwLDDsbaBuUBsV = MZruLjaCHHisXlGggo.join(fURHqbUkLGLgooKIjejU[6]);var vYtoxaRuGEC, fyz" ascii
    $s3  = "function nHPSGMpqGWgBEmtYDBQnIgr(jRDpPTeaUavlnaXtLwPdXCyF,vDQTANaI){return jRDpPTeaUavlnaXtLwPdXCyF.charAt(vDQTANaI);}" fullword ascii
    $s4  = "tring.fromCharCode(92)+fURHqbUkLGLgooKIjejU[4],true);" fullword ascii
    $s5  = "EC, fyzuZhSHLT);else VZhkzdzwbmeBS += zMxWEkkxejjRJVNN(vYtoxaRuGEC, fyzuZhSHLT, xeoorlEmCGqMnMPFb);} while (JpgozaoPGVcaFnCdLLjz" ascii
    $s6  = "function ydPZhGQZs(){return JecOKHsdtk(fURHqbUkLGLgooKIjejU[8],[1,5,7],fURHqbUkLGLgooKIjejU[9]);}" fullword ascii
    $s7  = "function zMxWEkkxejjRJVNN(IrkMVsMfMxJ,ZzJwSePrUYYVOOUNp,PEDTiZpqu){return String.fromCharCode(IrkMVsMfMxJ,ZzJwSePrUYYVOOUNp,PEDT" ascii
    $s8  = "var PGAClVGA = bIjgqOQSmf.createtextfile(VanDqXDdCZc.ExpandEnvironmentStrings(fURHqbUkLGLgooKIjejU[2]+fURHqbUkLGLgooKIjejU[3])+S" ascii
    $s9  = "function UXfKjR(JfDSzEFmfic,YMvkKJEjUi) {var ZFZVqadJDVnDtS=[fURHqbUkLGLgooKIjejU[15]];JfDSzEFmfic[ZFZVqadJDVnDtS[0]](YMvkKJEjUi" ascii
    $s10 = "function E(QuXBPEcDxrvMFEjUR){return String.fromCharCode(QuXBPEcDxrvMFEjUR);}" fullword ascii
    $s11 = "function FHZHjXKpLXzJmvmL(tFykYCgsuMZULFLO,PlPySDHWvnyfiooKuUOHq){return tFykYCgsuMZULFLO.indexOf(PlPySDHWvnyfiooKuUOHq);}" fullword ascii
    $s12 = "function WzKztEcqom(MKbdoeMgnPodn) {var LrQwLDDsbaBuUBsV = MZruLjaCHHisXlGggo.join(fURHqbUkLGLgooKIjejU[6]);var vYtoxaRuGEC, fyz" ascii
    $s13 = "push(\"D\");MZruLjaCHHisXlGggo.push(\"3\");MZruLjaCHHisXlGggo.push(\"E\");MZruLjaCHHisXlGggo.push(\"F\");MZruLjaCHHisXlGggo.push" ascii
    $s14 = "var bIjgqOQSmf=function(){return new ActiveXObject(fURHqbUkLGLgooKIjejU[0]);}();" fullword ascii
    $s15 = "function tZtNYRah(){return JecOKHsdtk(fURHqbUkLGLgooKIjejU[12],[0,3,6],fURHqbUkLGLgooKIjejU[13]);}" fullword ascii
    $s16 = "jBW < MKbdoeMgnPodn.length);return VZhkzdzwbmeBS;}" fullword ascii
    $s17 = "function zMxWEkkxejjRJVNN(IrkMVsMfMxJ,ZzJwSePrUYYVOOUNp,PEDTiZpqu){return String.fromCharCode(IrkMVsMfMxJ,ZzJwSePrUYYVOOUNp,PEDT" ascii
    $s18 = "function UXfKjR(JfDSzEFmfic,YMvkKJEjUi) {var ZFZVqadJDVnDtS=[fURHqbUkLGLgooKIjejU[15]];JfDSzEFmfic[ZFZVqadJDVnDtS[0]](YMvkKJEjUi" ascii
    $s19 = "function nhxyCbvef(sjozCJhtuymFuPW,pKXbVkn){return String.fromCharCode(sjozCJhtuymFuPW,pKXbVkn);}" fullword ascii
    $s20 = "function JecOKHsdtk(onxozLbFdT,schnNBZFhfOMOZ,BFVKAhLkVkqv){zVQegxOvrQDdI=onxozLbFdT.split(BFVKAhLkVkqv);bRifcJJijEJ = fURHqbUkL" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}