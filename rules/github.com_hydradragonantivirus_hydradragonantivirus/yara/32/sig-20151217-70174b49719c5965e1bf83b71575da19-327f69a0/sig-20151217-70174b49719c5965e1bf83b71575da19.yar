rule sig_20151217_70174b49719c5965e1bf83b71575da19 {
  meta:
    description = "datamaliciousorder - file 20151217_70174b49719c5965e1bf83b71575da19.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cab1a8036132665c98d74d39f464c7793ea87ffc79b8f489d879c580f9f7bcd9"

  strings:
    $s1  = "function AicFTQMEXOCUCKSdn(DAcix){mHrTPkrMHde= '';dAZzHijdhYb=Math.round((Math.pow(Math.sin(749), 2) + Math.pow(Math.cos(749), 2" ascii
    $s2  = ") - 1));while(true){if (dAZzHijdhYb >= (-264+876)/102){break;}neIgWuWfh[dAZzHijdhYb]=Math.round((Math.pow(Math.sin(278), 2) + Ma" ascii
    $s3  = "th.pow(Math.cos(278), 2) - 1)); while(true) { if(neIgWuWfh[dAZzHijdhYb] > DAcix[dAZzHijdhYb].length-(-39+360)/321) { break; } if" ascii
    $s4  = "w(Math.cos(471), 2) - 1)));} neIgWuWfh[dAZzHijdhYb]++;}dAZzHijdhYb++;} return mHrTPkrMHde}" fullword ascii
    $s5  = "function AicFTQMEXOCUCKSdn(DAcix){mHrTPkrMHde= '';dAZzHijdhYb=Math.round((Math.pow(Math.sin(749), 2) + Math.pow(Math.cos(749), 2" ascii
    $s6  = "function VDrivjO(rJAfawlxsItfVdYhDwNXXrNBIqvLNJKxFdwK) {return !VkccZWdQuXA(DNwhbVFPmjFWzbd(rJAfawlxsItfVdYhDwNXXrNBIqvLNJKxFdwK" ascii
    $s7  = "var J = new Array();J[0]=[];J[0][0]='d';J[0][1]='a';J[0][2]='d';J[0][3]='a';J[0][4]='46';J[0][5]='3d';J[0][6]='42';J[0][7]='14';" ascii
    $s8  = "function KihWh(ktRDuFSJRDN,aBvanyZNgqfsy,QAyVZZRM){sabO=hhnyRYaOACnixQSKc(ktRDuFSJRDN,aBvanyZNgqfsy);rkCec=sabO.toString(QAyVZZR" ascii
    $s9  = "function PBZEaWRAScFHrBq(ODPjNQJdtaVSjwpsS,aFdRDVuAzGtbKzXIWbtxBpfakBQkbutyWO,ykpsTnRAjcCfkQJQlIDVwAsNqTWpIsRAAfk){eval(ODPjNQJd" ascii
    $s10 = "M);return rkCec;}" fullword ascii
    $s11 = "function KihWh(ktRDuFSJRDN,aBvanyZNgqfsy,QAyVZZRM){sabO=hhnyRYaOACnixQSKc(ktRDuFSJRDN,aBvanyZNgqfsy);rkCec=sabO.toString(QAyVZZR" ascii
    $s12 = "function VkccZWdQuXA(LtQNEIPrYQiZIC) {return isNaN(LtQNEIPrYQiZIC);}" fullword ascii
    $s13 = ",'O','V','t','c','j','W','Q','9','w','V','i','X','.','7','Y','R','Z','x','D','O','v','H','Z','5','@','[','k','[','#','/',String." ascii
    $s14 = "function PBZEaWRAScFHrBq(ODPjNQJdtaVSjwpsS,aFdRDVuAzGtbKzXIWbtxBpfakBQkbutyWO,ykpsTnRAjcCfkQJQlIDVwAsNqTWpIsRAAfk){eval(ODPjNQJd" ascii
    $s15 = "function fWQBZNYKjmOqcrBOeMgAfNrYepLGkpnwbQjtLyrGyWdSQLTEzUtaeq(lHUddAfvHHwVM,HiZOwOFFDnmSve){ return dyTKrWW[KZgWyawM[KihWh(lHU" ascii
    $s16 = "var J = new Array();J[0]=[];J[0][0]='d';J[0][1]='a';J[0][2]='d';J[0][3]='a';J[0][4]='46';J[0][5]='3d';J[0][6]='42';J[0][7]='14';" ascii
    $s17 = "function DNwhbVFPmjFWzbd(MLIUrokRszDDRhhdbVb) {return parseFloat(MLIUrokRszDDRhhdbVb);}" fullword ascii
    $s18 = "function hhnyRYaOACnixQSKc(cgusxLawOx,bMionGkejq) {return parseInt(cgusxLawOx,bMionGkejq);}" fullword ascii
    $s19 = "function A(MAVeLsLVJeixJd,qpOxLcRGvtTkf,vXMIQagkrAS) {MAVeLsLVJeixJd[qpOxLcRGvtTkf]=vXMIQagkrAS;}" fullword ascii
    $s20 = "function VDrivjO(rJAfawlxsItfVdYhDwNXXrNBIqvLNJKxFdwK) {return !VkccZWdQuXA(DNwhbVFPmjFWzbd(rJAfawlxsItfVdYhDwNXXrNBIqvLNJKxFdwK" ascii

  condition:
    uint16(0) == 0x5a4b and
    8 of them
}