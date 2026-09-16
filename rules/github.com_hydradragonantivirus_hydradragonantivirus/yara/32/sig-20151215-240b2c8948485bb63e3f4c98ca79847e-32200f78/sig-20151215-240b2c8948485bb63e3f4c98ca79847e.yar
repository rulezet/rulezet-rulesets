rule sig_20151215_240b2c8948485bb63e3f4c98ca79847e {
  meta:
    description = "datamaliciousorder - file 20151215_240b2c8948485bb63e3f4c98ca79847e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e932b1431ac7d8326eb4caa88e1c90b9bebe5f89142edbaf27454fec9ad38a71"

  strings:
    $s1  = "ath.pow(Math.cos(164), 2) - 1)); while(true) { if(MyPlfTSQp[fIAzvbShZeT] > DHyIs[fIAzvbShZeT].length-(633+100)/733) { break; } i" ascii
    $s2  = "pow(Math.cos(660), 2) - 1)));} MyPlfTSQp[fIAzvbShZeT]++;}} return nowzBHDsqKe}" fullword ascii
    $s3  = "function pkoSGCjgBRzapJNGU(DHyIs){nowzBHDsqKe= c[1813];for(fIAzvbShZeT=Math.round((Math.pow(Math.sin(969), 2) + Math.pow(Math.co" ascii
    $s4  = "HYttsDqEKTxlxydXhrwmzTCzhaRBrwyusEP([DHyIs[fIAzvbShZeT][MyPlfTSQp[fIAzvbShZeT]]], Math.round((Math.pow(Math.sin(660), 2) + Math." ascii
    $s5  = "function pkoSGCjgBRzapJNGU(DHyIs){nowzBHDsqKe= c[1813];for(fIAzvbShZeT=Math.round((Math.pow(Math.sin(969), 2) + Math.pow(Math.co" ascii
    $s6  = "function j(toubDXjKfeBR,NuDFFzKbDbvjxw){toubDXjKfeBR.push(NuDFFzKbDbvjxw);}function J9(ntfjMdYkGaGqZILq){if(xbrqOZi(ntfjMdYkGaGq" ascii
    $s7  = "ZILq)) {return (String.fromCharCode(ntfjMdYkGaGqZILq) + String.fromCharCode((45243+55)/638));}}" fullword ascii
    $s8  = "function xbrqOZi(UzVnwTZCVnpKXaHAeDOYaYVTRMDKzqDnQtuj) {return !isNaN(parseFloat(UzVnwTZCVnpKXaHAeDOYaYVTRMDKzqDnQtuj)) && isFin" ascii
    $s9  = "function xbrqOZi(UzVnwTZCVnpKXaHAeDOYaYVTRMDKzqDnQtuj) {return !isNaN(parseFloat(UzVnwTZCVnpKXaHAeDOYaYVTRMDKzqDnQtuj)) && isFin" ascii
    $s10 = "function aFESaihcRmz(MiLoqrUN,UkLsuw){return MiLoqrUN.split(UkLsuw)}" fullword ascii
    $s11 = "var c=new Array();" fullword ascii
    $s12 = "function oZGFowLAriyZpDpcTImHYttsDqEKTxlxydXhrwmzTCzhaRBrwyusEP(FqolnuMJQTxzz,DUurzndzfkruor){ return kHevXOq[AYcfCKUh[bliNW(Fqo" ascii
    $s13 = "function oZGFowLAriyZpDpcTImHYttsDqEKTxlxydXhrwmzTCzhaRBrwyusEP(FqolnuMJQTxzz,DUurzndzfkruor){ return kHevXOq[AYcfCKUh[bliNW(Fqo" ascii
    $s14 = "function j(toubDXjKfeBR,NuDFFzKbDbvjxw){toubDXjKfeBR.push(NuDFFzKbDbvjxw);}function J9(ntfjMdYkGaGqZILq){if(xbrqOZi(ntfjMdYkGaGq" ascii
    $s15 = "function bliNW(ZCVsMCjnhPW,eCousoRNRVrMb,jDuENPYJ){WSXP=parseInt(ZCVsMCjnhPW,eCousoRNRVrMb);vYxiP=WSXP.toString(jDuENPYJ);return" ascii
    $s16 = "function bliNW(ZCVsMCjnhPW,eCousoRNRVrMb,jDuENPYJ){WSXP=parseInt(ZCVsMCjnhPW,eCousoRNRVrMb);vYxiP=WSXP.toString(jDuENPYJ);return" ascii
    $s17 = " vYxiP;}function OalFXFKVwMGTVpw(oKShfcrEbCkwRWvip,BUvkmJFRvfhgxNpNTnofYitPhUfDfljyru,PfIVfLMOIosbquRWqWLZmDgowcsyVjfDiBv){eval(" ascii
    $s18 = "function OalFXFKVwMGTVpw(oKShfcrEbCkwRWvip){eval(oKShfcrEbCkwRWvip)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}