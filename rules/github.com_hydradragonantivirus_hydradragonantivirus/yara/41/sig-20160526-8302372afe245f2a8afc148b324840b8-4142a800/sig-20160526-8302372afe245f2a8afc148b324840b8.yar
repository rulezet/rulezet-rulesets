rule sig_20160526_8302372afe245f2a8afc148b324840b8 {
  meta:
    description = "datamaliciousorder - file 20160526_8302372afe245f2a8afc148b324840b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f21d1a3dd2e01b37dbb721df123250d148a29824cd0d8b8ac82bc556fe7f7b44"

  strings:
    $s1  = "function zJCdpyEnojUcWu(XVtLYxXVOErpD) {var YFUoeLftOciGsQSOnpUiwI = EIhlJgzbWsMM.join(cjmiWknnCokhineoeqnVNko[0]);var fPFkvNK, " ascii
    $s2  = ") - 1))-109)) VslTjKqFkWN += TwgUxEsObWASWxyte(fPFkvNK, WpfrMtV);else VslTjKqFkWN += YtFEMPmlRrNkvMd(fPFkvNK, WpfrMtV, NGnqprfUX" ascii
    $s3  = ")) VslTjKqFkWN += zo(fPFkvNK);else if (bsfuUptLvORq == (173 + Math.round((Math.pow(Math.sin(264), 2) + Math.pow(Math.cos(264), 2" ascii
    $s4  = "function YtFEMPmlRrNkvMd(ihqtvxtqJqg,bbyZYUNqctxorThSM,SPYgQVkNvmFmye){return String.fromCharCode(ihqtvxtqJqg,bbyZYUNqctxorThSM," ascii
    $s5  = "function YtFEMPmlRrNkvMd(ihqtvxtqJqg,bbyZYUNqctxorThSM,SPYgQVkNvmFmye){return String.fromCharCode(ihqtvxtqJqg,bbyZYUNqctxorThSM," ascii
    $s6  = "function QjmysIuBTLI(ynzmNRhBScUZzJiiHgitxNoL,HhLFgeNq){return ynzmNRhBScUZzJiiHgitxNoL.charAt(HhLFgeNq);}" fullword ascii
    $s7  = "function xzLkLaKZOPTDbwWIcJhNWiu(yEnKqGdnodhAG,iNRfvloXbHkyrkLClXp){return yEnKqGdnodhAG.indexOf(iNRfvloXbHkyrkLClXp);}" fullword ascii
    $s8  = "function zJCdpyEnojUcWu(XVtLYxXVOErpD) {var YFUoeLftOciGsQSOnpUiwI = EIhlJgzbWsMM.join(cjmiWknnCokhineoeqnVNko[0]);var fPFkvNK, " ascii
    $s9  = "function zo(iSDkDZJNtPtkM){return String.fromCharCode(iSDkDZJNtPtkM);}" fullword ascii
    $s10 = "tohxTywKWCrC);} while (uAePPfFEDSETPJQtdTH < XVtLYxXVOErpD.length);return VslTjKqFkWN;}" fullword ascii
    $s11 = "function TwgUxEsObWASWxyte(fRakdeQmIpfS,eyiMbCAxXcdsOBT){return String.fromCharCode(fRakdeQmIpfS,eyiMbCAxXcdsOBT);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}