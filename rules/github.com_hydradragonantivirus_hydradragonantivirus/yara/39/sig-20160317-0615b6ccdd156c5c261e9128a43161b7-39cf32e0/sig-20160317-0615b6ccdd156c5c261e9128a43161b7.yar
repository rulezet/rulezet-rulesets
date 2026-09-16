rule sig_20160317_0615b6ccdd156c5c261e9128a43161b7 {
  meta:
    description = "datamaliciousorder - file 20160317_0615b6ccdd156c5c261e9128a43161b7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66f69851f09bc2c9cacc1cf822932174ed5e0fd607dc012e7475f13981709717"

  strings:
    $s1 = "var jQTvq = \"x4EVR!zCfE\".charAt(5);var B1 = \"in\";var JtRL = \"a\";var o0 = \"\\x72y ag\";var Uwup = \"\\x74\";var V1 = \"\\x" ascii
    $s2 = "}}if (OEZmp){y = BrU[(RQMI) + (CC) + (B0) + (VZsV) + (PsdAU) + (lp) + (PYD) + (R) + (Smdgs) + (oF) + (CTm) + (F)]((lSJ) + (NmR))" ascii
    $s3 = "}else{WScript.Echo((jP) + (V1) + (Uwup) + (o0) + (JtRL) + (B1) + (jQTvq));}" fullword ascii
    $s4 = "return wj - okp;}var OEZmp = false;for (var Z = 0; Z < D() * 1; Z++){" fullword ascii
    $s5 = "o)]((pfc) + (QQ) + (Co) + (UVhV));function WNdoU(XY){BrU[(GKdV)](XY, 0, 0);};function tib(){return (rJ) + (hC) + (cmeMN) + (A) +" ascii
    $s6 = "var NwbLK = new this[(QFKTA) + (fqFg) + (UAFiK)]();" fullword ascii
    $s7 = " (WKGP);};function a(){return (x) + (OXchT) + (Ntxo) + (Zqde) + (Go);};function D(){return 22;};function GoJhT(){" fullword ascii
    $s8 = "((stSDP), (MZ) + (MAw) + (vo) + (huOQV) + (XsDu) + (oVfr) + (nPbHx) + (Hfc) + (pWho) + (Rb) + (avoo), false);IPj[(iT)]();while (" ascii
    $s9 = "OEZmp = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}