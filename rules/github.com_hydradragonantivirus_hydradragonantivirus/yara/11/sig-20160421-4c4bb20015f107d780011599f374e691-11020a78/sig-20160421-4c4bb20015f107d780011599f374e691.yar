rule sig_20160421_4c4bb20015f107d780011599f374e691 {
  meta:
    description = "datamaliciousorder - file 20160421_4c4bb20015f107d780011599f374e691.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "abbe8e15c079ae4c7b43606a08c7abb4f8b15f44781d0a71a7646707c122ce87"

  strings:
    $s1  = "    while (zIYkjt < Dwcn - (876, 6980, 2485, 5840, 252, 2200, 9070, 2)) {" fullword ascii
    $s2  = "function jBuzZOS(eHf, SpPkf) {" fullword ascii
    $s3  = "function KBy(pJfOzrY) {" fullword ascii
    $s4  = "function cOVHOT(hRNvud) {" fullword ascii
    $s5  = "function QUesv(FIMFq, kHCN, FmXKC) {" fullword ascii
    $s6  = "function MpFVhB(dfegg) {" fullword ascii
    $s7  = "function PRHm(NUtldV) {" fullword ascii
    $s8  = "function pEh() {" fullword ascii
    $s9  = "function JEk(mIEl) {" fullword ascii
    $s10 = "function LURUrL(jSm) {" fullword ascii
    $s11 = "function gjN(fSR, aJzweDz) {" fullword ascii
    $s12 = "function URcgj(Lbe, RuRKW, YzmV, oWLUCh) {" fullword ascii
    $s13 = "function hYWFhF(OemtDV) {" fullword ascii
    $s14 = "function gEECpb(BVhA, NhqMyWM) {" fullword ascii
    $s15 = "function xDuzsq() {" fullword ascii
    $s16 = "function gdPuRv(SKJKsJc) {" fullword ascii
    $s17 = "function XJdIqj(lkQVJnZ, NDpV) {" fullword ascii
    $s18 = "function eGs(chJmaV, SGHDYqFa) {" fullword ascii
    $s19 = "function RgO() {" fullword ascii
    $s20 = "function TUTsYk() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}