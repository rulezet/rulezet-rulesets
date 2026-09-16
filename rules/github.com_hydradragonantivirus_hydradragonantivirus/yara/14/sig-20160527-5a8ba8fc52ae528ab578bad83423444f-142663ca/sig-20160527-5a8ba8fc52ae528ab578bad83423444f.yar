rule sig_20160527_5a8ba8fc52ae528ab578bad83423444f {
  meta:
    description = "datamaliciousorder - file 20160527_5a8ba8fc52ae528ab578bad83423444f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59ce9ca9cd95e73104bdb29df254c7c850c50eff33776bd959a1d6bd2647039c"

  strings:
    $s1  = "function JSeIWDBouvdDB() {return WScript;}function eGzSBpwSFutbNX(){return qPFOa.ExpandEnvironmentStrings(BNwsQMagq())}" fullword ascii
    $s2  = "function VNOpreLPzyzqHjmeTQ(nHqfwwXRNkgCxmzU,PuXJXRmdSKYAqGC){return nHqfwwXRNkgCxmzU.charAt(PuXJXRmdSKYAqGC);}" fullword ascii
    $s3  = "function JfbIliRZJziaCYKK(uMyuiPwrlAxsOMGiupC,SgcsTDQZeRv){return String.fromCharCode(uMyuiPwrlAxsOMGiupC,SgcsTDQZeRv);}" fullword ascii
    $s4  = "Dm < RXUvhuNcwNlpR.length);return dcoVGGChEysSFDNTOtrmM;}" fullword ascii
    $s5  = "XEDOq, wjqqIDdEPQg);else dcoVGGChEysSFDNTOtrmM += RqFJvvIkaZOO(hsyEvOQWJEWQgMBQXEDOq, wjqqIDdEPQg, OhLZngN);} while (CDdaCNouwWz" ascii
    $s6  = "function JFmtRD(){return NwiDhgCq(IwCfNcEeGJZvkjUBUVe[10],[2,4,8,10],IwCfNcEeGJZvkjUBUVe[11]);}" fullword ascii
    $s7  = "function RqFJvvIkaZOO(lGuqUUjGkOeEOtbH,xLQlLivEzBWPC,iuqVpTVEOMVsh){return String.fromCharCode(lGuqUUjGkOeEOtbH,xLQlLivEzBWPC,iu" ascii
    $s8  = "function BNwsQMagq(){return NwiDhgCq(IwCfNcEeGJZvkjUBUVe[8],[1,5,7],IwCfNcEeGJZvkjUBUVe[9]);}" fullword ascii
    $s9  = "function RqFJvvIkaZOO(lGuqUUjGkOeEOtbH,xLQlLivEzBWPC,iuqVpTVEOMVsh){return String.fromCharCode(lGuqUUjGkOeEOtbH,xLQlLivEzBWPC,iu" ascii
    $s10 = "function aaEOhWWcsK(xvqnVhdCXIqAopqbufXW,mReglnsqJIfCe){return xvqnVhdCXIqAopqbufXW.indexOf(mReglnsqJIfCe);}" fullword ascii
    $s11 = "function andgdEfRfrfX(RXUvhuNcwNlpR) {var TzhwOcdFwsexGzNbWsB = JnAJZdCO.join(IwCfNcEeGJZvkjUBUVe[6]);var hsyEvOQWJEWQgMBQXEDOq," ascii
    $s12 = "var qPFOa=function(){return JSeIWDBouvdDB().CreateObject(IwCfNcEeGJZvkjUBUVe[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s13 = "+= TC(hsyEvOQWJEWQgMBQXEDOq);else if (wcGIFRGVOqPFayYCImgOSrjr == 64) dcoVGGChEysSFDNTOtrmM += JfbIliRZJziaCYKK(hsyEvOQWJEWQgMBQ" ascii
    $s14 = "function qwlSUOxQTISNze(TmGSVBTzHqT,suvrZzk) {var XSICNii=[IwCfNcEeGJZvkjUBUVe[15]];TmGSVBTzHqT[XSICNii[0]](suvrZzk,0x1,0x0)}" fullword ascii
    $s15 = "function BtUtBrmoDzML(){return NwiDhgCq(IwCfNcEeGJZvkjUBUVe[12],[0,3,6],IwCfNcEeGJZvkjUBUVe[13]);}" fullword ascii
    $s16 = "function TC(lWTwnvxThHvjNhEi){return String.fromCharCode(lWTwnvxThHvjNhEi);}" fullword ascii
    $s17 = "var reEUOgwl=function(){return new ActiveXObject(IwCfNcEeGJZvkjUBUVe[0]);}();" fullword ascii
    $s18 = "var NoRsXKkix = reEUOgwl.createtextfile(qPFOa.ExpandEnvironmentStrings(IwCfNcEeGJZvkjUBUVe[2]+IwCfNcEeGJZvkjUBUVe[3])+String.fro" ascii
    $s19 = "function andgdEfRfrfX(RXUvhuNcwNlpR) {var TzhwOcdFwsexGzNbWsB = JnAJZdCO.join(IwCfNcEeGJZvkjUBUVe[6]);var hsyEvOQWJEWQgMBQXEDOq," ascii
    $s20 = "mCharCode(92)+IwCfNcEeGJZvkjUBUVe[4],true);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}