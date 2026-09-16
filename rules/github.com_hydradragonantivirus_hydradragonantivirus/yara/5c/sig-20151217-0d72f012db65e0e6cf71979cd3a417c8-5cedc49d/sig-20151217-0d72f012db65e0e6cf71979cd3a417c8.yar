rule sig_20151217_0d72f012db65e0e6cf71979cd3a417c8 {
  meta:
    description = "datamaliciousorder - file 20151217_0d72f012db65e0e6cf71979cd3a417c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f4c3dea2c4696de314b53198c3661b320c23060ca367b5c0d51c9477f6ff792"

  strings:
    $s1  = ") - 1));while(true){if (sFUBrGRZuZU >= (702+762)/244){break;}FboClalUT[sFUBrGRZuZU]=Math.round((Math.pow(Math.sin(868), 2) + Mat" ascii
    $s2  = "function GxGuMupayrNCXoVwZ(lzQeZ){mdKuaZQhTKU= '';sFUBrGRZuZU=Math.round((Math.pow(Math.sin(859), 2) + Math.pow(Math.cos(859), 2" ascii
    $s3  = "h.pow(Math.cos(868), 2) - 1)); while(true) { if(FboClalUT[sFUBrGRZuZU] > lzQeZ[sFUBrGRZuZU].length-(419+499)/918) { break; } if " ascii
    $s4  = "(Math.cos(738), 2) - 1)));} FboClalUT[sFUBrGRZuZU]++;}sFUBrGRZuZU++;} return mdKuaZQhTKU}" fullword ascii
    $s5  = "function GxGuMupayrNCXoVwZ(lzQeZ){mdKuaZQhTKU= '';sFUBrGRZuZU=Math.round((Math.pow(Math.sin(859), 2) + Math.pow(Math.cos(859), 2" ascii
    $s6  = "function lkvHZrG(AKqcDculvannJqYicMoshIfpDuhekVuEBOKP) {return !mMVJWtYjywD(WVxYjIyIMCxymBQ(AKqcDculvannJqYicMoshIfpDuhekVuEBOKP" ascii
    $s7  = "var N = new Array();N[0]=[];N[0][0]='d';N[0][1]='a';N[0][2]='d';N[0][3]='a';N[0][4]='46';N[0][5]='3d';N[0][6]='42';N[0][7]='14';" ascii
    $s8  = ",'=','V','D','u','j','W','i',';','m','X','[',',','k',':','^','h','0','V','Y','h','Z','y','8','z','E','%','F','w','[',')',String." ascii
    $s9  = "function l(vWUJSqpoIkdB,EdRUmipAdEXIpw){vWUJSqpoIkdB.push(EdRUmipAdEXIpw);}" fullword ascii
    $s10 = "function NrFaVxbtIJwwoRD(ktjhjiGHJIcpFfPlD,mbOwhyRlMsRJtWkJJhfJcFxeucekCghCRm,pgQUygvwelacfRxwyeUXEspqeSTENVJhuwI){eval(ktjhjiGH" ascii
    $s11 = "function NxtEJ(oAIHimCqRfh,bySvsbQGbWPlg,zFXqaizd){CMIR=TiWvmufMzwOszpCFG(oAIHimCqRfh,bySvsbQGbWPlg);cYjYg=CMIR.toString(zFXqaiz" ascii
    $s12 = "function TiWvmufMzwOszpCFG(XdCkBnTIMR,VJJxrlqWhi) {return parseInt(XdCkBnTIMR,VJJxrlqWhi);}" fullword ascii
    $s13 = "d);return cYjYg;}" fullword ascii
    $s14 = "var N = new Array();N[0]=[];N[0][0]='d';N[0][1]='a';N[0][2]='d';N[0][3]='a';N[0][4]='46';N[0][5]='3d';N[0][6]='42';N[0][7]='14';" ascii
    $s15 = "function iTTIjuYyayjotZxYECPXdMhuzWhMXOwjJkHPnPUInPHOlyigroxXWH(WLiSrcsOQLrOl,SQapSxbthwGIXg){ return XwWpFou[EwQdBVUW[NxtEJ(WLi" ascii
    $s16 = "function WVxYjIyIMCxymBQ(rJQPPIIZLTAeFVzTNIz) {return parseFloat(rJQPPIIZLTAeFVzTNIz);}" fullword ascii
    $s17 = "function iTTIjuYyayjotZxYECPXdMhuzWhMXOwjJkHPnPUInPHOlyigroxXWH(WLiSrcsOQLrOl,SQapSxbthwGIXg){ return XwWpFou[EwQdBVUW[NxtEJ(WLi" ascii
    $s18 = "function k(MDHDVEvmKaWnPR,TwCHcTPBigQIw,gWMCBYNnpPd) {MDHDVEvmKaWnPR[TwCHcTPBigQIw]=gWMCBYNnpPd;}" fullword ascii
    $s19 = "function mMVJWtYjywD(lfYYJPmLilQZHd) {return isNaN(lfYYJPmLilQZHd);}" fullword ascii
    $s20 = "function NrFaVxbtIJwwoRD(ktjhjiGHJIcpFfPlD,mbOwhyRlMsRJtWkJJhfJcFxeucekCghCRm,pgQUygvwelacfRxwyeUXEspqeSTENVJhuwI){eval(ktjhjiGH" ascii

  condition:
    uint16(0) == 0x7745 and
    8 of them
}