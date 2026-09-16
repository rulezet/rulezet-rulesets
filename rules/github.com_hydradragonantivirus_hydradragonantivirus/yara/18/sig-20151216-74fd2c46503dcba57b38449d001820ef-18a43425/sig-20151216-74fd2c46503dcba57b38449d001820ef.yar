rule sig_20151216_74fd2c46503dcba57b38449d001820ef {
  meta:
    description = "datamaliciousorder - file 20151216_74fd2c46503dcba57b38449d001820ef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c84877494e4a94fec7441f209729994ffea463f9dd7a180ea46960071b12e5de"

  strings:
    $s1  = ") - 1));while(true){if (raImRcrSEuz >= (1084+530)/269){break;}pzNndmPlf[raImRcrSEuz]=Math.round((Math.pow(Math.sin(782), 2) + Ma" ascii
    $s2  = "th.pow(Math.cos(782), 2) - 1)); while(true) { if(pzNndmPlf[raImRcrSEuz] > uhiQk[raImRcrSEuz].length-(-630+860)/230) { break; } i" ascii
    $s3  = "pow(Math.cos(537), 2) - 1)));} pzNndmPlf[raImRcrSEuz]++;}raImRcrSEuz++;} return AfaNsFyXvGu}" fullword ascii
    $s4  = "function nmfRjTEfLUiRRXfMM(uhiQk){AfaNsFyXvGu= '';raImRcrSEuz=Math.round((Math.pow(Math.sin(620), 2) + Math.pow(Math.cos(620), 2" ascii
    $s5  = "hcXOrfewbGRcvMBBHMZpBpHXrKFiwZbkJUo([uhiQk[raImRcrSEuz][pzNndmPlf[raImRcrSEuz]]], Math.round((Math.pow(Math.sin(537), 2) + Math." ascii
    $s6  = "function nmfRjTEfLUiRRXfMM(uhiQk){AfaNsFyXvGu= '';raImRcrSEuz=Math.round((Math.pow(Math.sin(620), 2) + Math.pow(Math.cos(620), 2" ascii
    $s7  = "function MdEOAKbvdHp(GeTCWTyKivVsEW) {return isNaN(GeTCWTyKivVsEW);}" fullword ascii
    $s8  = "function ZYNGUqW(jiBOodVxIXWtkBiOGfKzKLujLFKDeVgdoash) {return !MdEOAKbvdHp(XJUNAQzvcMkjXKv(jiBOodVxIXWtkBiOGfKzKLujLFKDeVgdoash" ascii
    $s9  = "function GFYNwUprgsPfDTN(iGzhUXBLbtGWUWmSD,awrESroIXgwrYsvlcsMoDvJBwNPLhPLEXK,VCSgwnpcomigcTvSTblJuNZOdvpdhXIMqTM){eval(iGzhUXBL" ascii
    $s10 = "function GFYNwUprgsPfDTN(iGzhUXBLbtGWUWmSD,awrESroIXgwrYsvlcsMoDvJBwNPLhPLEXK,VCSgwnpcomigcTvSTblJuNZOdvpdhXIMqTM){eval(iGzhUXBL" ascii
    $s11 = "var T = new Array();T[0]=[];T[0][0]='d';T[0][1]='a';T[0][2]='d';T[0][3]='a';T[0][4]='46';T[0][5]='3d';T[0][6]='42';T[0][7]='14';" ascii
    $s12 = "e);return wlmwy;}" fullword ascii
    $s13 = "function a(urqFtFCYUTLe,JztJIHAbFTuwZF){urqFtFCYUTLe.push(JztJIHAbFTuwZF);}" fullword ascii
    $s14 = "function ZYNGUqW(jiBOodVxIXWtkBiOGfKzKLujLFKDeVgdoash) {return !MdEOAKbvdHp(XJUNAQzvcMkjXKv(jiBOodVxIXWtkBiOGfKzKLujLFKDeVgdoash" ascii
    $s15 = "function XJUNAQzvcMkjXKv(zELwOBBawUVtEKJWFCy) {return parseFloat(zELwOBBawUVtEKJWFCy);}" fullword ascii
    $s16 = "var T = new Array();T[0]=[];T[0][0]='d';T[0][1]='a';T[0][2]='d';T[0][3]='a';T[0][4]='46';T[0][5]='3d';T[0][6]='42';T[0][7]='14';" ascii
    $s17 = "function NjWtxTRJXvbD(aQlqLEHqoIaKE) {return isFinite(aQlqLEHqoIaKE);}" fullword ascii
    $s18 = "function YtikitmnOkjLfDWSHgAhcXOrfewbGRcvMBBHMZpBpHXrKFiwZbkJUo(YCSiGNleLyVHI,igqASfakSfpDcG){ return yjiZuYw[FonmaAKy[rlxoU(YCS" ascii
    $s19 = "function rlxoU(otkBJHFwzSu,eOHBaTyoBAwia,jabckLHe){IBuu=oTNrJtqIlquwUiuli(otkBJHFwzSu,eOHBaTyoBAwia);wlmwy=IBuu.toString(jabckLH" ascii
    $s20 = "function YtikitmnOkjLfDWSHgAhcXOrfewbGRcvMBBHMZpBpHXrKFiwZbkJUo(YCSiGNleLyVHI,igqASfakSfpDcG){ return yjiZuYw[FonmaAKy[rlxoU(YCS" ascii

  condition:
    uint16(0) == 0x6f46 and
    8 of them
}