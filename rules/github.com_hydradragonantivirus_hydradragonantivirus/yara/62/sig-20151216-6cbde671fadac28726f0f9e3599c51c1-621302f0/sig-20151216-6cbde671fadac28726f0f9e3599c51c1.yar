rule sig_20151216_6cbde671fadac28726f0f9e3599c51c1 {
  meta:
    description = "datamaliciousorder - file 20151216_6cbde671fadac28726f0f9e3599c51c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce1492b0994264ed1148259c276e8b4ae1430936401f40841dce0be556cceef3"

  strings:
    $s1  = "ath.cos(920), 2) - 1)));} zbYwTeyFz[qevKUthkooG]++;}qevKUthkooG++;} return yuhtzFfbXmC}" fullword ascii
    $s2  = "function ZJYfbRzSaahjdrfWn(VYCEL){yuhtzFfbXmC= '';qevKUthkooG=Math.round((Math.pow(Math.sin(471), 2) + Math.pow(Math.cos(471), 2" ascii
    $s3  = ") - 1));while(true){if (qevKUthkooG >= (4436+58)/749){break;}zbYwTeyFz[qevKUthkooG]=Math.round((Math.pow(Math.sin(140), 2) + Mat" ascii
    $s4  = "h.pow(Math.cos(140), 2) - 1)); while(true) { if(zbYwTeyFz[qevKUthkooG] > VYCEL[qevKUthkooG].length-(157+475)/632) { break; } if " ascii
    $s5  = "function ZJYfbRzSaahjdrfWn(VYCEL){yuhtzFfbXmC= '';qevKUthkooG=Math.round((Math.pow(Math.sin(471), 2) + Math.pow(Math.cos(471), 2" ascii
    $s6  = "function FYRsGol(OxCWnKkYgodiTQzpqxDezItOmtvTQBRvatsF) {return !yizccXrtdNK(tvbFJxbgZlIvDPM(OxCWnKkYgodiTQzpqxDezItOmtvTQBRvatsF" ascii
    $s7  = "var u = new Array();u[0]=[];u[0][0]='d';u[0][1]='a';u[0][2]='d';u[0][3]='a';u[0][4]='46';u[0][5]='3d';u[0][6]='42';u[0][7]='14';" ascii
    $s8  = "var u = new Array();u[0]=[];u[0][0]='d';u[0][1]='a';u[0][2]='d';u[0][3]='a';u[0][4]='46';u[0][5]='3d';u[0][6]='42';u[0][7]='14';" ascii
    $s9  = "function FYRsGol(OxCWnKkYgodiTQzpqxDezItOmtvTQBRvatsF) {return !yizccXrtdNK(tvbFJxbgZlIvDPM(OxCWnKkYgodiTQzpqxDezItOmtvTQBRvatsF" ascii
    $s10 = "function tvbFJxbgZlIvDPM(cchZuvBwaUZvooAdSWS) {return parseFloat(cchZuvBwaUZvooAdSWS);}" fullword ascii
    $s11 = "function UeDDjfiEheYOhfmCeqxqgxdHpyslDseTtENqVuLWHKHXOAqmVRNXeS(ieKAsLvSYlCMa,xHGjswfKyMlsEl){ return QoBKxXF[GqnIpPoT[mWDDS(ieK" ascii
    $s12 = "function d(nbVbVXnDOqVi,WSxSaqYDVNCxbt){nbVbVXnDOqVi.push(WSxSaqYDVNCxbt);}" fullword ascii
    $s13 = "function yizccXrtdNK(piguUXOjFAozGH) {return isNaN(piguUXOjFAozGH);}" fullword ascii
    $s14 = "function NkJDWOgpGpQGJWyKF(jYNmAmbaSq,hCrFxpwgvt) {return parseInt(jYNmAmbaSq,hCrFxpwgvt);}" fullword ascii
    $s15 = "function UeDDjfiEheYOhfmCeqxqgxdHpyslDseTtENqVuLWHKHXOAqmVRNXeS(ieKAsLvSYlCMa,xHGjswfKyMlsEl){ return QoBKxXF[GqnIpPoT[mWDDS(ieK" ascii
    $s16 = "function mPgMoYCsMYeO(fLNhzsVArchGZ) {return isFinite(fLNhzsVArchGZ);}" fullword ascii
    $s17 = "function E(wOFDWwmGiPYMmt,vgYwcXoPAGFhO,FUNBsuoLZgd) {wOFDWwmGiPYMmt[vgYwcXoPAGFhO]=FUNBsuoLZgd;}" fullword ascii
    $s18 = "i);return NTPNd;}" fullword ascii
    $s19 = "function clSObYofDAASRUQ(MguMxXRMvfkbEpYwm,xTTNcNelQUZcRZhYfQTejcpnqNmXYZBEva,NyGIGQStCOqLLqPpDPhmiIIcapFKDwzLyIv){eval(MguMxXRM" ascii
    $s20 = "function mWDDS(SBUDryhNPNX,xwJcAouTwSHPG,NszoJqmi){SBzM=NkJDWOgpGpQGJWyKF(SBUDryhNPNX,xwJcAouTwSHPG);NTPNd=SBzM.toString(NszoJqm" ascii

  condition:
    uint16(0) == 0x7147 and
    8 of them
}