rule sig_20151217_0f447bdcb5db464366ba8096bffe908f {
  meta:
    description = "datamaliciousorder - file 20151217_0f447bdcb5db464366ba8096bffe908f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ccd7ea312e036000cb8492e93a97b5378291f173ce63d655a05e04deb5ccaf69"

  strings:
    $s1  = ".pow(Math.cos(28), 2) - 1)); while(true) { if(sMnQAzAdx[BjHXbKffKLq] > SrfUk[BjHXbKffKLq].length-(678+244)/922) { break; } if (A" ascii
    $s2  = ") - 1));while(true){if (BjHXbKffKLq >= (795+891)/281){break;}sMnQAzAdx[BjHXbKffKLq]=Math.round((Math.pow(Math.sin(28), 2) + Math" ascii
    $s3  = "function gzFczYghUAxnmZzGc(SrfUk){hpBRSOeUsiu= '';BjHXbKffKLq=Math.round((Math.pow(Math.sin(299), 2) + Math.pow(Math.cos(299), 2" ascii
    $s4  = "(Math.cos(359), 2) - 1)));} sMnQAzAdx[BjHXbKffKLq]++;}BjHXbKffKLq++;} return hpBRSOeUsiu}" fullword ascii
    $s5  = "function gzFczYghUAxnmZzGc(SrfUk){hpBRSOeUsiu= '';BjHXbKffKLq=Math.round((Math.pow(Math.sin(299), 2) + Math.pow(Math.cos(299), 2" ascii
    $s6  = "function AseDrex(CGNSUVSvPKCeWYWrzFQPyvpqpLYOPhvtlZpi) {return !KaJfPStNtFj(uNeDagbbuBhVswL(CGNSUVSvPKCeWYWrzFQPyvpqpLYOPhvtlZpi" ascii
    $s7  = "var e = new Array();e[0]=[];e[0][0]='d';e[0][1]='a';e[0][2]='d';e[0][3]='a';e[0][4]='46';e[0][5]='3d';e[0][6]='42';e[0][7]='14';" ascii
    $s8  = "function CNiagWloYAAfPzAONPBkiSUumKXYxJXeiUWtRowuOcQZmQapOUerBz(iZoccqMOGCjmU,zztHeUAuYaaIMW){ return kRAOfkj[kavIFKKQ[gSgeR(iZo" ascii
    $s9  = "function uNeDagbbuBhVswL(EChIcBXsvbjBZeBaidW) {return parseFloat(EChIcBXsvbjBZeBaidW);}" fullword ascii
    $s10 = "function s(AEOreAVzmhXI,LnCjSTeyDLBDck){AEOreAVzmhXI.push(LnCjSTeyDLBDck);}" fullword ascii
    $s11 = "function gSgeR(XIfmzeLYJvk,syFFmreSKjIRm,vCqjelOs){diXo=cOycXyJmoDFKxmeRU(XIfmzeLYJvk,syFFmreSKjIRm);VuwlX=diXo.toString(vCqjelO" ascii
    $s12 = "function AseDrex(CGNSUVSvPKCeWYWrzFQPyvpqpLYOPhvtlZpi) {return !KaJfPStNtFj(uNeDagbbuBhVswL(CGNSUVSvPKCeWYWrzFQPyvpqpLYOPhvtlZpi" ascii
    $s13 = "function ltoWvyxQLLmBEfV(JjZFTDSFsqhtPFCsk,rUDypuOXKSGLHvEeeOZjXZNHLQumYRICEr,CsnnJaxZsoExBHGzXzmiWsULzcSAYMZbiKk){eval(JjZFTDSF" ascii
    $s14 = "function cOycXyJmoDFKxmeRU(CDxvVstfFF,TSFFOHPylw) {return parseInt(CDxvVstfFF,TSFFOHPylw);}" fullword ascii
    $s15 = "function gSgeR(XIfmzeLYJvk,syFFmreSKjIRm,vCqjelOs){diXo=cOycXyJmoDFKxmeRU(XIfmzeLYJvk,syFFmreSKjIRm);VuwlX=diXo.toString(vCqjelO" ascii
    $s16 = "function KaJfPStNtFj(JuYfVqkDqcTvdh) {return isNaN(JuYfVqkDqcTvdh);}" fullword ascii
    $s17 = "function ltoWvyxQLLmBEfV(JjZFTDSFsqhtPFCsk,rUDypuOXKSGLHvEeeOZjXZNHLQumYRICEr,CsnnJaxZsoExBHGzXzmiWsULzcSAYMZbiKk){eval(JjZFTDSF" ascii
    $s18 = "function CNiagWloYAAfPzAONPBkiSUumKXYxJXeiUWtRowuOcQZmQapOUerBz(iZoccqMOGCjmU,zztHeUAuYaaIMW){ return kRAOfkj[kavIFKKQ[gSgeR(iZo" ascii
    $s19 = "s);return VuwlX;}" fullword ascii
    $s20 = "var e = new Array();e[0]=[];e[0][0]='d';e[0][1]='a';e[0][2]='d';e[0][3]='a';e[0][4]='46';e[0][5]='3d';e[0][6]='42';e[0][7]='14';" ascii

  condition:
    uint16(0) == 0x616b and
    8 of them
}