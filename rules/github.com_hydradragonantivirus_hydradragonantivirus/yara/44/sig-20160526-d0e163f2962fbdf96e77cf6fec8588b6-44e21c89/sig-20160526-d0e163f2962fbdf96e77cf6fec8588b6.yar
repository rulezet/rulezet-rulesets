rule sig_20160526_d0e163f2962fbdf96e77cf6fec8588b6 {
  meta:
    description = "datamaliciousorder - file 20160526_d0e163f2962fbdf96e77cf6fec8588b6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b327d8ff65a74d832527cd6bf58886bfbfc6e2805ae3819c2cfc20bbcb414d5"

  strings:
    $s1  = "function ilwIKaMQ(ogZASfnUsyCSf) {var pxULkcCtzQCkq = jgKsZKsjkzkJAVByfkBUun.join(WiFifX[0]);var LjgbwuKDKtHVx, pydau, ENUXlDsQi" ascii
    $s2  = "h.sin(890), 2) + Math.pow(Math.cos(890), 2) - 1))-579)) JrKfwo += D(LjgbwuKDKtHVx);else if (WFJmTRptDcvNIFAFlNbayDHe == (825 + M" ascii
    $s3  = "function eQriakaWGxcNDAEbl(sbZxCBv,WopSCdHHg){return sbZxCBv.charAt(WopSCdHHg);}" fullword ascii
    $s4  = "function ilwIKaMQ(ogZASfnUsyCSf) {var pxULkcCtzQCkq = jgKsZKsjkzkJAVByfkBUun.join(WiFifX[0]);var LjgbwuKDKtHVx, pydau, ENUXlDsQi" ascii
    $s5  = "function rncJtIlgIXPjWlAmZd(KhylYgySjGxRESrvFDZSI,Igozsk){return String.fromCharCode(KhylYgySjGxRESrvFDZSI,Igozsk);}" fullword ascii
    $s6  = "function D(dxLoXANjwxhitViubeSfRa){return String.fromCharCode(dxLoXANjwxhitViubeSfRa);}" fullword ascii
    $s7  = ");else JrKfwo += OCddwOqxywguCXptXBZTdWN(LjgbwuKDKtHVx, pydau, ENUXlDsQim);} while (zDseokeKKC < ogZASfnUsyCSf.length);return Jr" ascii
    $s8  = "function OCddwOqxywguCXptXBZTdWN(xUowTkPySbq,oFSWegpGxBVdgXQXdBBQNjLH,pCJtXeEELB){return String.fromCharCode(xUowTkPySbq,oFSWegp" ascii
    $s9  = "function HsHyqfsMELQfQpooHDF(BbCrIEBnuByAKoCQGGxR,PNooK){return BbCrIEBnuByAKoCQGGxR.indexOf(PNooK);}" fullword ascii
    $s10 = "function OCddwOqxywguCXptXBZTdWN(xUowTkPySbq,oFSWegpGxBVdgXQXdBBQNjLH,pCJtXeEELB){return String.fromCharCode(xUowTkPySbq,oFSWegp" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}