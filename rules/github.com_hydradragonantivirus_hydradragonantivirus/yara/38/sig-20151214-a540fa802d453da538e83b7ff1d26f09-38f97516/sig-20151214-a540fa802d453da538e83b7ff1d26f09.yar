rule sig_20151214_a540fa802d453da538e83b7ff1d26f09 {
  meta:
    description = "datamaliciousorder - file 20151214_a540fa802d453da538e83b7ff1d26f09.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e46351173b2f68efbfb2884cec0bef732d6553d57e5f71bbfbe052e5c0878ee5"

  strings:
    $s1  = "Math.pow(Math.cos(130), 2) - 1)); while(true) { if(wvrXlqwsv[UIvvYNXjSKc] > JjfaM[UIvvYNXjSKc].length-(-35+125)/90) { break; } i" ascii
    $s2  = "w(Math.cos(619), 2) - 1)));} wvrXlqwsv[UIvvYNXjSKc]++;}} return wRPscALcbpf}" fullword ascii
    $s3  = "function HUyEkmmGOiYQzQDnq(JjfaM){wRPscALcbpf= E[1775];for(UIvvYNXjSKc=Math.round((Math.pow(Math.sin(749), 2) + Math.pow(Math.co" ascii
    $s4  = "function SgZTq(OZfTrNrbVeK,qnJhNTltshJNR,uieNhpFo){ZDWO=parseInt(OZfTrNrbVeK,qnJhNTltshJNR);gwmuQ=ZDWO.toString(uieNhpFo);return" ascii
    $s5  = " gwmuQ;}function hgyfANofNsLwzMy(StfAVStXJhNtMHAFi,lRsTHvQfwlLogqMIrsTzMHujXKnpqeXChC,AHCrbSGWRYpuzHzlvhxujiEmmQIfShqkKje){eval(" ascii
    $s6  = "KIYz)) {return (String.fromCharCode(fZSvVvCQSxeQKIYz) + String.fromCharCode((15397+857)/258));}}" fullword ascii
    $s7  = "function W(ZReZZFBDxQHT,KlMyALKKrzlvKL){ZReZZFBDxQHT.push(KlMyALKKrzlvKL);}function J7(fZSvVvCQSxeQKIYz){if(ngwHZJB(fZSvVvCQSxeQ" ascii
    $s8  = "function ngwHZJB(JlCZabXHsiwrtDBscjSxplkYzIfTUodEWvPy) {return !isNaN(parseFloat(JlCZabXHsiwrtDBscjSxplkYzIfTUodEWvPy)) && isFin" ascii
    $s9  = "function HUyEkmmGOiYQzQDnq(JjfaM){wRPscALcbpf= E[1775];for(UIvvYNXjSKc=Math.round((Math.pow(Math.sin(749), 2) + Math.pow(Math.co" ascii
    $s10 = "function ngwHZJB(JlCZabXHsiwrtDBscjSxplkYzIfTUodEWvPy) {return !isNaN(parseFloat(JlCZabXHsiwrtDBscjSxplkYzIfTUodEWvPy)) && isFin" ascii
    $s11 = "function W(ZReZZFBDxQHT,KlMyALKKrzlvKL){ZReZZFBDxQHT.push(KlMyALKKrzlvKL);}function J7(fZSvVvCQSxeQKIYz){if(ngwHZJB(fZSvVvCQSxeQ" ascii
    $s12 = "function NwBJLVLgbAb(NtLTuiKr,RxhlLq){return NtLTuiKr.split(RxhlLq)}" fullword ascii
    $s13 = "var E=new Array();" fullword ascii
    $s14 = "function SgZTq(OZfTrNrbVeK,qnJhNTltshJNR,uieNhpFo){ZDWO=parseInt(OZfTrNrbVeK,qnJhNTltshJNR);gwmuQ=ZDWO.toString(uieNhpFo);return" ascii
    $s15 = "function hgyfANofNsLwzMy(StfAVStXJhNtMHAFi){eval(StfAVStXJhNtMHAFi)}" fullword ascii
    $s16 = "function NXEaAXPYgqHQtyYavfDNGvyTXRNsrXRPaMMDYbIXAgpwxXURrEOTBt(oUARtDXyocJDT,WFaqkFzkEbLRsv){ return VZYuFQZ[wBDGecaY[SgZTq(oUA" ascii
    $s17 = "function NXEaAXPYgqHQtyYavfDNGvyTXRNsrXRPaMMDYbIXAgpwxXURrEOTBt(oUARtDXyocJDT,WFaqkFzkEbLRsv){ return VZYuFQZ[wBDGecaY[SgZTq(oUA" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}