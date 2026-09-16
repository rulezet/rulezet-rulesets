rule sig_20151217_4c8170444060ba5ce87b7ce33db2c4d1 {
  meta:
    description = "datamaliciousorder - file 20151217_4c8170444060ba5ce87b7ce33db2c4d1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69dd9abb9a97df940e005445f07d1caae4299fe5b4c372e88bac7c9771277ab8"

  strings:
    $s1  = "Math.cos(911), 2) - 1)));} HOgepiJRp[yMIzzuoAWLk]++;}yMIzzuoAWLk++;} return bLXkuuPKVPy}" fullword ascii
    $s2  = ") - 1));while(true){if (yMIzzuoAWLk >= (5235+327)/927){break;}HOgepiJRp[yMIzzuoAWLk]=Math.round((Math.pow(Math.sin(374), 2) + Ma" ascii
    $s3  = "th.pow(Math.cos(374), 2) - 1)); while(true) { if(HOgepiJRp[yMIzzuoAWLk] > DcNNn[yMIzzuoAWLk].length-(-14+19)/5) { break; } if (B" ascii
    $s4  = "function mMtNQOPBuXKyOTXcZ(DcNNn){bLXkuuPKVPy= '';yMIzzuoAWLk=Math.round((Math.pow(Math.sin(197), 2) + Math.pow(Math.cos(197), 2" ascii
    $s5  = "function mMtNQOPBuXKyOTXcZ(DcNNn){bLXkuuPKVPy= '';yMIzzuoAWLk=Math.round((Math.pow(Math.sin(197), 2) + Math.pow(Math.cos(197), 2" ascii
    $s6  = "function BQmAzOx(TJzFIClVFQLxeWLgttgCzNrasVcdLpUskVVY) {return !DKmNvtWolgj(maOIzdPefjfEalU(TJzFIClVFQLxeWLgttgCzNrasVcdLpUskVVY" ascii
    $s7  = "var h = new Array();h[0]=[];h[0][0]='d';h[0][1]='a';h[0][2]='d';h[0][3]='a';h[0][4]='46';h[0][5]='3d';h[0][6]='42';h[0][7]='14';" ascii
    $s8  = "function cgFDJoRjkpXN(viDOCGLWXNMCT) {return isFinite(viDOCGLWXNMCT);}" fullword ascii
    $s9  = "function K(SyrXAqYMEIXhHk,jqBqDPFmnPRvv,yLjPCFuNafo) {SyrXAqYMEIXhHk[jqBqDPFmnPRvv]=yLjPCFuNafo;}" fullword ascii
    $s10 = "function AtmDZ(NoPhyHHTRwJ,IsNpwYGkVnogk,bXBEkeiP){nrMF=nSLMwsekPsECzhBbV(NoPhyHHTRwJ,IsNpwYGkVnogk);ptPTN=nrMF.toString(bXBEkei" ascii
    $s11 = "function BQmAzOx(TJzFIClVFQLxeWLgttgCzNrasVcdLpUskVVY) {return !DKmNvtWolgj(maOIzdPefjfEalU(TJzFIClVFQLxeWLgttgCzNrasVcdLpUskVVY" ascii
    $s12 = "P);return ptPTN;}" fullword ascii
    $s13 = "function AtmDZ(NoPhyHHTRwJ,IsNpwYGkVnogk,bXBEkeiP){nrMF=nSLMwsekPsECzhBbV(NoPhyHHTRwJ,IsNpwYGkVnogk);ptPTN=nrMF.toString(bXBEkei" ascii
    $s14 = "function rOdIHAJYwQwmCHE(FNdNMTjahARwTgBoQ,VxTstwTjynCzvZnIGZAopiROodAxGUgOcU,ABVDSCRrCBIZlnkzhUYKBsKlxfbjJpqaKsK){eval(FNdNMTja" ascii
    $s15 = "function i(lPidWDFQqKJV,FbSGJiRDITNaGq){lPidWDFQqKJV.push(FbSGJiRDITNaGq);}" fullword ascii
    $s16 = "var h = new Array();h[0]=[];h[0][0]='d';h[0][1]='a';h[0][2]='d';h[0][3]='a';h[0][4]='46';h[0][5]='3d';h[0][6]='42';h[0][7]='14';" ascii
    $s17 = "function maOIzdPefjfEalU(BBgToBYfNizRBFTvsgt) {return parseFloat(BBgToBYfNizRBFTvsgt);}" fullword ascii
    $s18 = "function rOdIHAJYwQwmCHE(FNdNMTjahARwTgBoQ,VxTstwTjynCzvZnIGZAopiROodAxGUgOcU,ABVDSCRrCBIZlnkzhUYKBsKlxfbjJpqaKsK){eval(FNdNMTja" ascii
    $s19 = "function fKwWpJdaeFRPIyirtTubYrQFLQiGZpToRidDmwAztzgcZpFRpqzVlg(YJGLJWTvSqfEH,NJHDHaxsTqYhNl){ return wxNXwfo[XYqiqynA[AtmDZ(YJG" ascii
    $s20 = "function nSLMwsekPsECzhBbV(McFeyIjPNd,JVcqpMXmcU) {return parseInt(McFeyIjPNd,JVcqpMXmcU);}" fullword ascii

  condition:
    uint16(0) == 0x5958 and
    8 of them
}