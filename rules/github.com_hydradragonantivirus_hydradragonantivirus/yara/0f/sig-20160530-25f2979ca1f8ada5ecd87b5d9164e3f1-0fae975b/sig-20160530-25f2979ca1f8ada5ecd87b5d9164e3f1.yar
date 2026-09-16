rule sig_20160530_25f2979ca1f8ada5ecd87b5d9164e3f1 {
  meta:
    description = "datamaliciousorder - file 20160530_25f2979ca1f8ada5ecd87b5d9164e3f1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50425298af2b7b8a4a9cc5733395348ebfea2f639617bc9cd7cec8c1de56e3e7"

  strings:
    $s1  = "var YeprlnyClCpdAQ=function(){return WScript.CreateObject(rXZHx[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function BCQzZu(RWRFwysp,nOvkqVgZnsGDjyJbOKfjTwE){return RWRFwysp.charAt(nOvkqVgZnsGDjyJbOKfjTwE);}" fullword ascii
    $s3  = "function yrBINNaEZLGXTL(){return iTDihDolzWiadd(rXZHx[13],[0,3,6],rXZHx[14]);}" fullword ascii
    $s4  = "RXSiTIHYvAax.length);return MyrkCTz;}" fullword ascii
    $s5  = "function VIfDsDCJdxqz(){return iTDihDolzWiadd(rXZHx[9],[1,5,7],rXZHx[10]);}" fullword ascii
    $s6  = "bALQRyCpp<LNouCZ.length;aobbALQRyCpp++) {qBwqf+=qMXmHQj[LNouCZ[aobbALQRyCpp]];}return qBwqf.substring(3,qBwqf.length);}" fullword ascii
    $s7  = "function eWXEsaT(dRXSiTIHYvAax) {var zeiBzBwmL = eWClLUyrqFtIlziUoZG.join(rXZHx[7]);var STlIsQ, dtKzfvYFEeHPtK, wnGQNWrLRjnb, tU" ascii
    $s8  = "function iTDihDolzWiadd(FWPYz,LNouCZ,nFtEYFKicXUwJm){qMXmHQj=FWPYz.split(nFtEYFKicXUwJm);qBwqf = rXZHx[0];for(aobbALQRyCpp=0;aob" ascii
    $s9  = "function leyxgjQuHLPZPa(kAkhbfeuGgeOnAeoebZXi,oZpMHoxAVkqAZmp){return String.fromCharCode(kAkhbfeuGgeOnAeoebZXi,oZpMHoxAVkqAZmp)" ascii
    $s10 = "function WbQRgHEH(aFScWMi,NCgfAxySgHKX) {var WPlfZzwJHzEbS=[rXZHx[15]];aFScWMi[WPlfZzwJHzEbS[0]]" fullword ascii
    $s11 = "function eWXEsaT(dRXSiTIHYvAax) {var zeiBzBwmL = eWClLUyrqFtIlziUoZG.join(rXZHx[7]);var STlIsQ, dtKzfvYFEeHPtK, wnGQNWrLRjnb, tU" ascii
    $s12 = "WrLRjnb = NxVRlvmaDVKJQCffJyoJRk & 0xff;if (TaeDbIqTqqModYz == 64) MyrkCTz += OL(STlIsQ);else if (jbjvAawbev == 64) MyrkCTz += l" ascii
    $s13 = "function iTDihDolzWiadd(FWPYz,LNouCZ,nFtEYFKicXUwJm){qMXmHQj=FWPYz.split(nFtEYFKicXUwJm);qBwqf = rXZHx[0];for(aobbALQRyCpp=0;aob" ascii
    $s14 = "function zvBpXcFLrtGy(){return iTDihDolzWiadd(rXZHx[11],[2,4,8,10],rXZHx[12]);}" fullword ascii
    $s15 = "var ugGYeDvFtdyuwC = ezZhle.createtextfile(YeprlnyClCpdAQ.ExpandEnvironmentStrings(rXZHx[3]+rXZHx[4])+String.fromCharCode(92)+rX" ascii
    $s16 = "function wgUyvV(sWdKJb,EaDhXjrqBFSBJXKl,yOlyuCEIlGrFEqQQPB){return String.fromCharCode(sWdKJb,EaDhXjrqBFSBJXKl,yOlyuCEIlGrFEqQQP" ascii
    $s17 = "function XOnKJQpVMCZRJlieDJc(ramPORgiJA,xloJnGCkprEVmSl){return ramPORgiJA.indexOf(xloJnGCkprEVmSl);}" fullword ascii
    $s18 = "eyxgjQuHLPZPa(STlIsQ, dtKzfvYFEeHPtK);else MyrkCTz += wgUyvV(STlIsQ, dtKzfvYFEeHPtK, wnGQNWrLRjnb);} while (FhmwLFtklmKmCwIj < d" ascii
    $s19 = "function wgUyvV(sWdKJb,EaDhXjrqBFSBJXKl,yOlyuCEIlGrFEqQQPB){return String.fromCharCode(sWdKJb,EaDhXjrqBFSBJXKl,yOlyuCEIlGrFEqQQP" ascii
    $s20 = "function EGszKL(){return YeprlnyClCpdAQ.ExpandEnvironmentStrings(VIfDsDCJdxqz())}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}