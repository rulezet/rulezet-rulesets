rule sig_20160526_7f9fded9d53110416971e3241faf8193 {
  meta:
    description = "datamaliciousorder - file 20160526_7f9fded9d53110416971e3241faf8193.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "490d9b92de8dfc5ce7ff5587a896d52fbaa41c8cc81ae9a504e5a940c5157157"

  strings:
    $s1  = "nd((Math.pow(Math.sin(548), 2) + Math.pow(Math.cos(548), 2) - 1))-58)) rdGjXGwQiqoZrsG += kk(XDhdFqY);else if (VuFVgGMHOEUvp == " ascii
    $s2  = "function qycKxFfARgFr(rjEOPnWyPbNyr) {var bfkgzQwZXFuFNRDVjyO = WLBRxoxpmyenQUmACayj.join(pXkSJkmCbPXBognZdN[0]);var XDhdFqY, Ow" ascii
    $s3  = "function nRyMKyPqsuqp(CjEXnKJEFSJfqdQUyDs,TpocJHZ){return CjEXnKJEFSJfqdQUyDs.charAt(TpocJHZ);}" fullword ascii
    $s4  = "bNyr.length);return rdGjXGwQiqoZrsG;}" fullword ascii
    $s5  = "function MHWrjGBShNflgOVxlHtc(sbuUnpwVssJKK,FKWQTojJVdbPxIWdJRRIBND){return String.fromCharCode(sbuUnpwVssJKK,FKWQTojJVdbPxIWdJR" ascii
    $s6  = "function MHWrjGBShNflgOVxlHtc(sbuUnpwVssJKK,FKWQTojJVdbPxIWdJRRIBND){return String.fromCharCode(sbuUnpwVssJKK,FKWQTojJVdbPxIWdJR" ascii
    $s7  = "function WIKDUUdDvs(bDTIITOr,ooXGJAgv,IBqfSFiTbxy){return String.fromCharCode(bDTIITOr,ooXGJAgv,IBqfSFiTbxy);}" fullword ascii
    $s8  = "function VtPePzEKLrC(RszBKSGONKmBWEz,haBddAKfEHcfMmnTCFNc){return RszBKSGONKmBWEz.indexOf(haBddAKfEHcfMmnTCFNc);}" fullword ascii
    $s9  = "function kk(YKGDLEYNDiVFsylyPtEgj){return String.fromCharCode(YKGDLEYNDiVFsylyPtEgj);}" fullword ascii
    $s10 = "function qycKxFfARgFr(rjEOPnWyPbNyr) {var bfkgzQwZXFuFNRDVjyO = WLBRxoxpmyenQUmACayj.join(pXkSJkmCbPXBognZdN[0]);var XDhdFqY, Ow" ascii
    $s11 = "DhdFqY, OwzXtlE);else rdGjXGwQiqoZrsG += WIKDUUdDvs(XDhdFqY, OwzXtlE, ohAPyUUvCAcKBpcmSotib);} while (GCqiaubqVlDchf < rjEOPnWyP" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}