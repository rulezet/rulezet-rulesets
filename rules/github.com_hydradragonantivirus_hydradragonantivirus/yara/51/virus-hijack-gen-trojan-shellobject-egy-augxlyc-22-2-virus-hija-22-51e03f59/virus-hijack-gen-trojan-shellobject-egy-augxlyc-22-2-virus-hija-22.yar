import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_eGY_augxLYc_22_2_Virus_Hija_22 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.eGY@augxLYc_22_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.eGY@augxLYc_23_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.eGY@augxLYc_24_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0ae723adbed4d20ef9f0352c6bc5a458784cd45a0d1153e0e814f1ebc82b5b9"
    hash2       = "f973a348fa2944207bbcff8e789191f195df3215e8a094123dd6245ca24e0d91"
    hash3       = "31dfa61d54e68824d06e268710c492461de3f5fa5fad2aab169fbc35ef9dcf7d"

  strings:
    $s1  = "9w8wEn=o=o=q=r=s=x=u=v=wBiAx>j>kEt>m>n>o>p>q>r>s:t>u>v>w>x?i?j?k?l?m?n?o?p?q?r?s?t?u?v?w?x@i@j@k@l@m@n@o@p@q@r@s@t@u@v@wGpAiAjAk" ascii
    $s2  = ">u<s>vGtAi>u>sAlAvGnGnCv;l:xGmAl:nAvGjFp:rEvEl>m9i9vAsGu>k9qCl<jCk:j9mCw:n=t<kGl8vEo@x:mCt?j@iBo9mAu;jDr:s<xGkFpEmAn:k=s<wDtAoCm" ascii
    $s3  = "Au;xGm9j?sBp8q=m?u=qEkAi:k>i=m?vGoFp9u?w?j?jAmAn@xEuAuBo<nBsBw;m@sCwAn;vEuBxCt<n@qFr?lBv=j=p<sEtDs<j=oGtEi?x:i@mFj<m>wCmEk8tGt;o" ascii
    $s4  = "9w:mCqBu>k>pFn=pDnGv>kFtDtAl>uDrBvFmDnBk<lAmEl<nDw@x<uBiGq;nAnBl9j<lDx8l>r=q<t?n8v8p8iFu?xEwDoEp?oFlAv9sDuFmDjCqGjFtEs<sDrEn>m:p" ascii
    $s5  = "AwAt;lCi@u8u>jEj@oEwFx9lFvAoCoCl:oFuFu<jDr8kBkFmAi9rDiAm<sEp>o8r:p<m:t;u=vGwDrBuFv8w>v9rBmDt:oCv?u?u<i=rEv?p?jBn8u8jAq<iAmGt;pGv" ascii
    $s6  = "GoGo?sBx9u@jCv>s>l@vDj<xCk<n@o<t@q;pCs>j9iCsAl?r:s8k<s;oBsAk:nDp;tEvDoFp;i9oAo@s;kDi9k8tEv9pCkGpCwDp?x;wGnGtCuCn8l:i;l9qCsFpGm@o" ascii
    $s7  = "Gl?n<x8rCnCi<m;lFwCiEq<xEj9s<nExAl<t?rCx>i<jCmFu?qEp9k@q>u>wGpAm<r?r>x=s;t9q9s?oAuBr<k=o>o@nGk>j9q<u<wCk=i>v<u8l>j>oBkFnGr@jAoFj" ascii
    $s8  = "Bi:wAvClBlGw9uDt@r?u@pCo8lAi:u@sFr8n?k=t8lAj>o8i;vEn8uCmCkGu@r=s=uGm;x>o<tBj;tAvEr>x?xDs>sAsCrFwGn@nFi?sGl=x:v<lFx@o8x9u8jFp?sGt" ascii
    $s9  = "AxAkAsBjBiAkDkEu;kBl=x;x<s=v>xDn>w:jFj;q8lCr@n:sCj9iGiGw;mGxDq>tGs<pArEr>t:o;uAx<l?xDp<u9iGp8q@j:qBjEiDx9iEi>tGiBs8j>q:xArEl8xEq" ascii
    $s10 = "Fo;kElEk<k@sAm=s8p9w>x;m;tBsEs=j=rAk?mAuCv9mAx:l@l>n=v;x@xAo<k>tDjEpDl?v@q>lBx>i>mCtGk=x>vEwAo:pDrBvEw?k@oBx>mAn9j>k:u;sCnBp>iCt" ascii
    $s11 = "GoAt>r?q@n8lDxDuGnAtCjFm@v>x;n@m9vGsEj@u=sFp9x:xGlGq<qBn:q<o8n:wCk;o8qBlAv<u8r8qFmFl9m?qEwAj8pEtCn@w8nCxFiDn;o>u=u8oAkGs>o=s;l?r" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "5fa5234c56c604654f201a027c1f2ff7" and (8 of them)
    ) or (all of them)
}