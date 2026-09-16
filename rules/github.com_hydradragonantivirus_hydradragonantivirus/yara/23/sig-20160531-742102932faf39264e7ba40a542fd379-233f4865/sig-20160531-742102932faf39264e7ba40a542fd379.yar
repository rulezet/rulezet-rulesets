rule sig_20160531_742102932faf39264e7ba40a542fd379 {
  meta:
    description = "datamaliciousorder - file 20160531_742102932faf39264e7ba40a542fd379.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c769491ac229b4e5cf35a89683aee8abf2ea5896b8c82da25ad6b7b7d7efacc4"

  strings:
    $s1  = "var XDipZDPbYXHF=function(){return WScript.CreateObject(qQKjlHtEFLFQbZZc[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function XcUKNbLTZMJoPolltiGs(nMdwtpRMzkmerUMrZtdwlvvm,SYhMgfsxbTQMXnHd){return nMdwtpRMzkmerUMrZtdwlvvm.charAt(SYhMgfsxbTQMXnHd" ascii
    $s3  = "function XcUKNbLTZMJoPolltiGs(nMdwtpRMzkmerUMrZtdwlvvm,SYhMgfsxbTQMXnHd){return nMdwtpRMzkmerUMrZtdwlvvm.charAt(SYhMgfsxbTQMXnHd" ascii
    $s4  = "64) goeDm += dtgNbTLDPztnyjRWJVh(DuWUiNhBaJNdhu, juyeHtWIzoGAmN);else goeDm += MYGHr(DuWUiNhBaJNdhu, juyeHtWIzoGAmN, sCcTW);} wh" ascii
    $s5  = "function iFiAkcFFfc(UlMMlHyBMGlOm) {var DHeuVcJkphLGRR = fQTyNNMCOs.join(qQKjlHtEFLFQbZZc[7]);var DuWUiNhBaJNdhu, juyeHtWIzoGAmN" ascii
    $s6  = "function MYGHr(LXDlwGrgDQKEQqrFp,qWJyghFCwLrWe,rIOMTrzRDqXDkakVfT){return String.fromCharCode(LXDlwGrgDQKEQqrFp,qWJyghFCwLrWe,rI" ascii
    $s7  = "ile (KMmKCyonCUFasqhRbGSFQQGg < UlMMlHyBMGlOm.length);return goeDm;}" fullword ascii
    $s8  = "true);OjVCvaTNuPNj.WriteLine(jhoBMUJGM);OjVCvaTNuPNj.Close();}" fullword ascii
    $s9  = "function l(fMXsX){return String.fromCharCode(fMXsX);}" fullword ascii
    $s10 = "function cSJHwrUKspKQ(SlNPn,FhjqqlJ) {var aWNJMLEYcywN=[qQKjlHtEFLFQbZZc[15]];SlNPn[aWNJMLEYcywN[0]]" fullword ascii
    $s11 = "(FhjqqlJ,0x1,0x0)}function pCMkNhclhLB(tNXsHYhJ,xUSncBZnjTqWe,jhoBMUJGM){var OjVCvaTNuPNj=tNXsHYhJ.createtextfile(xUSncBZnjTqWe," ascii
    $s12 = "function QfqNuhcSpELDFmguWNEVc(LfrDfaPZmlLsZq,gtvdfXE){return LfrDfaPZmlLsZq.indexOf(gtvdfXE);}" fullword ascii
    $s13 = "CoTuAnM=0;EKwSnfZCoTuAnM<xJfWsJglGIvv.length;EKwSnfZCoTuAnM++) {orOUzaxQcZKfd+=GFirHZBw[xJfWsJglGIvv[EKwSnfZCoTuAnM]];}return or" ascii
    $s14 = "push(\"K\");fQTyNNMCOs.push(\"L\");fQTyNNMCOs.push(\"a\");fQTyNNMCOs.push(\"b\");fQTyNNMCOs.push(\"c\");fQTyNNMCOs.push(\"P\");f" ascii
    $s15 = "function IJVbyov(){return XDipZDPbYXHF.ExpandEnvironmentStrings(ItJNmXdoRqV())}" fullword ascii
    $s16 = "(FhjqqlJ,0x1,0x0)}function pCMkNhclhLB(tNXsHYhJ,xUSncBZnjTqWe,jhoBMUJGM){var OjVCvaTNuPNj=tNXsHYhJ.createtextfile(xUSncBZnjTqWe," ascii
    $s17 = "function iFiAkcFFfc(UlMMlHyBMGlOm) {var DHeuVcJkphLGRR = fQTyNNMCOs.join(qQKjlHtEFLFQbZZc[7]);var DuWUiNhBaJNdhu, juyeHtWIzoGAmN" ascii
    $s18 = "function UzjIwFjcLPTSIj(){return WKFuFCzMaCK(qQKjlHtEFLFQbZZc[13],[0,3,6],qQKjlHtEFLFQbZZc[14]);}" fullword ascii
    $s19 = "function MYGHr(LXDlwGrgDQKEQqrFp,qWJyghFCwLrWe,rIOMTrzRDqXDkakVfT){return String.fromCharCode(LXDlwGrgDQKEQqrFp,qWJyghFCwLrWe,rI" ascii
    $s20 = "function WKFuFCzMaCK(WeykduWu,xJfWsJglGIvv,AWZik){GFirHZBw=WeykduWu.split(AWZik);orOUzaxQcZKfd = qQKjlHtEFLFQbZZc[0];for(EKwSnfZ" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}