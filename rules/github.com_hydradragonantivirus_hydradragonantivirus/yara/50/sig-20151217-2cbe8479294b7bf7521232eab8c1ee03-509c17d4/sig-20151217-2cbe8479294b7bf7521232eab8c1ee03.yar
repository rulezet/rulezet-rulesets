rule sig_20151217_2cbe8479294b7bf7521232eab8c1ee03 {
  meta:
    description = "datamaliciousorder - file 20151217_2cbe8479294b7bf7521232eab8c1ee03.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa2d221ad34a90280b285ce10d9d07eb610fe8cdc115b22b64dd5a76797cb629"

  strings:
    $s1  = "function nkVkhYPUTKqctQXoZ(sDDyH){gWekQhVcXdE= '';xrAuFdXGuzO=Math.round((Math.pow(Math.sin(253), 2) + Math.pow(Math.cos(253), 2" ascii
    $s2  = "pow(Math.cos(318), 2) - 1)));} VNYCEDhQE[xrAuFdXGuzO]++;}xrAuFdXGuzO++;} return gWekQhVcXdE}" fullword ascii
    $s3  = ") - 1));while(true){if (xrAuFdXGuzO >= (2185+479)/444){break;}VNYCEDhQE[xrAuFdXGuzO]=Math.round((Math.pow(Math.sin(670), 2) + Ma" ascii
    $s4  = "th.pow(Math.cos(670), 2) - 1)); while(true) { if(VNYCEDhQE[xrAuFdXGuzO] > sDDyH[xrAuFdXGuzO].length-(-301+916)/615) { break; } i" ascii
    $s5  = "function nkVkhYPUTKqctQXoZ(sDDyH){gWekQhVcXdE= '';xrAuFdXGuzO=Math.round((Math.pow(Math.sin(253), 2) + Math.pow(Math.cos(253), 2" ascii
    $s6  = "NFnRPqFqesHERPmhummmZaYepVwEKuytCbD([sDDyH[xrAuFdXGuzO][VNYCEDhQE[xrAuFdXGuzO]]], Math.round((Math.pow(Math.sin(318), 2) + Math." ascii
    $s7  = "function IfMTzHS(AetCubVIUlyVUkqwKjtwGBUmogluolZsUpRE) {return !CWEhvFQBAMG(dOQkNvXsrSMZdvI(AetCubVIUlyVUkqwKjtwGBUmogluolZsUpRE" ascii
    $s8  = "var v = new Array();v[0]=[];v[0][0]='d';v[0][1]='a';v[0][2]='d';v[0][3]='a';v[0][4]='46';v[0][5]='3d';v[0][6]='42';v[0][7]='14';" ascii
    $s9  = "function I(LpwPZMCwPVajrE,cfsVPMaOAqPiP,fSybGJgjsua) {LpwPZMCwPVajrE[cfsVPMaOAqPiP]=fSybGJgjsua;}" fullword ascii
    $s10 = "function qdrSIhJHxSeh(tNMecPIIGeJWu) {return isFinite(tNMecPIIGeJWu);}" fullword ascii
    $s11 = "function t(LDabvAEoXjro,ONDQTGXAWxoexk){LDabvAEoXjro.push(ONDQTGXAWxoexk);}" fullword ascii
    $s12 = "A);return BCGCZ;}" fullword ascii
    $s13 = "function dOQkNvXsrSMZdvI(LuInNrSEAYqEjIpecwh) {return parseFloat(LuInNrSEAYqEjIpecwh);}" fullword ascii
    $s14 = "function fOkUj(kXdCyfCDgze,CGUYCYCTJMkNs,tXiAGWLA){pyxs=laLVhMZtanvDHAIvi(kXdCyfCDgze,CGUYCYCTJMkNs);BCGCZ=pyxs.toString(tXiAGWL" ascii
    $s15 = "function IfMTzHS(AetCubVIUlyVUkqwKjtwGBUmogluolZsUpRE) {return !CWEhvFQBAMG(dOQkNvXsrSMZdvI(AetCubVIUlyVUkqwKjtwGBUmogluolZsUpRE" ascii
    $s16 = "function laLVhMZtanvDHAIvi(HCGZtFTHaa,judPnjJjHK) {return parseInt(HCGZtFTHaa,judPnjJjHK);}" fullword ascii
    $s17 = "function fOkUj(kXdCyfCDgze,CGUYCYCTJMkNs,tXiAGWLA){pyxs=laLVhMZtanvDHAIvi(kXdCyfCDgze,CGUYCYCTJMkNs);BCGCZ=pyxs.toString(tXiAGWL" ascii
    $s18 = "var v = new Array();v[0]=[];v[0][0]='d';v[0][1]='a';v[0][2]='d';v[0][3]='a';v[0][4]='46';v[0][5]='3d';v[0][6]='42';v[0][7]='14';" ascii
    $s19 = "function CWEhvFQBAMG(uZvEzNPOJJUdBF) {return isNaN(uZvEzNPOJJUdBF);}" fullword ascii
    $s20 = "function jLzEOhLGdcpeuDYzXHuNFnRPqFqesHERPmhummmZaYepVwEKuytCbD(INNjAfejZcLBx,JauZjpEkleOItI){ return uOYlbRQ[acaUyhrk[fOkUj(INN" ascii

  condition:
    uint16(0) == 0x6361 and
    8 of them
}