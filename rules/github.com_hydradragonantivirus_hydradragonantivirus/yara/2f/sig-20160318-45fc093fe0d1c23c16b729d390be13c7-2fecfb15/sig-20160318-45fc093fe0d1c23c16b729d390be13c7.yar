rule sig_20160318_45fc093fe0d1c23c16b729d390be13c7 {
  meta:
    description = "datamaliciousorder - file 20160318_45fc093fe0d1c23c16b729d390be13c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c771c432aab3e4026cecc6d024137c8ceff9c55a05c5bd95bcceae1a880b918"

  strings:
    $s1  = "var ogq = \"ain!\";var EFU = \"3xLMgb\"[\"charAt\"](4);var hd = \"a\";var xx = \"y\\x20\";var wW = \", tr\";var FbPcF = \"ea\\x7" ascii
    $s2  = "CTi = \"t6\"[\"charAt\"](0);var TNAhv = \"Ob\\x6a\\x65c\";var L = \"re\\x61te\";var CM = \"C\";var w = function xSH() {return WS" ascii
    $s3  = "A0(){return hERtE;}()); VQSN = lGdKl(); xkddx = WScript[(function KS(){return CM;}()) + (L) + (function TH(){return TNAhv;}()) +" ascii
    $s4  = "urn kJfg;}()) + (function T(){return YzGgW;}()) + (function LZ(){return yD;}());}else{WScript.Echo((TYQA) + (function H0(){retur" ascii
    $s5  = "HnQV) + (function fhXT(){return L0;}()) + (function Yqn(){return l;}())]();WScript[(function rtTYu(){return dugeC;}()) + (functi" ascii
    $s6  = "turn YD;}()) + (function IivwP(){return zFZ;}()) + (DpT) + (kHnQV) + (L0) + (function c(){return l;}())]();WScript[(dugeC) + (Co" ascii
    $s7  = ") + (s2) + (function o0(){return tbK;}())] < 4 ) {WScript[(function xvQsL(){return dugeC;}()) + (CoTO)](gilr() * 10)};BrpmF = WS" ascii
    $s8  = " nzX){return lSzL - nzX;};function ybfMd(){return (function oRs(){return CM;}()) + (function N(){return L;}()) + (TNAhv) + (func" ascii
    $s9  = "turn v && Tw;};if (s()){rkpda = w[(function x0(){return rP;}()) + (function rVEmH(){return B;}()) + (gthA) + (function eHM(){ret" ascii
    $s10 = "bQ4\"[\"charAt\"](5);var gukO = \"Cr\";var R0 = \"T\\x54\\x50\";var BQov = \"LkgHkcM6\"[\"charAt\"](3);var OhdPQ = \"2.\\x58\\x4" ascii
    $s11 = "n FbPcF;}()) + (function kiixg(){return wW;}()) + (function Debh(){return xx;}()) + (hd) + (function YwwdC(){return EFU;}()) + (" ascii
    $s12 = "}()) + (function wFZ(){return OhdPQ;}()) + (function pGD(){return BQov;}()) + (function pU(){return R0;}());};function KCU(lSzL," ascii
    $s13 = "eturn osYu;}()) + (function OZx(){return MDPJ;}()) + (function WSkQ(){return tnR;}())]);BrpmF[(function BqaJC(){return KeqCX;}()" ascii
    $s14 = " (WUn) + (function CWUG(){return WLdV;}())]((wa) + (olif) + (o)) + (function RN(){return M0;}()) + (c0) + (function UwU(){return" ascii
    $s15 = "cript[ybfMd()]((function Km(){return bAN;}()) + (j0) + (DCiH));BrpmF[((function vzaCe(){return wHODO;}()))]();BrpmF[(TG)] = 1;Br" ascii
    $s16 = "()) + (VTu) + (function dBA(){return Wk;}()) + (function soGS(){return sjvza;}()) + (R2) + (DLop) + (function GL(){return FtmdL;" ascii
    $s17 = " YbQ;}()) + (function C(){return GzBx;}()) + (function KCtGG(){return CgV;}()) + (function FbNDA(){return pcMY;}()) + (function " ascii
    $s18 = "pmF[(function hzb(){return WxGmJ;}()) + (function cqmsQ(){return D0;}())](xkddx[(function vk(){return bZ;}()) + (function J0(){r" ascii
    $s19 = "urn aco;}()) + (vXtD) + (function FCpcD(){return E;}()) + (function Tlueq(){return ar;}()) + (function ZYs(){return qHPqh;}()) +" ascii
    $s20 = " + (function OLYr(){return oSkEm;}())]();while (xkddx[(function MBokg(){return bkMdl;}()) + (function L1(){return ZZQ;}()) + (lt" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}