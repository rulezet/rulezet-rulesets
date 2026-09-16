rule sig_76553952866_April_13_2019 {
  meta:
    description = "datamaliciousorder - file 76553952866_April_13_2019.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0819ed578beb38c8875532613ff761b6b4816f653ee41042f853fb87cdb592d"

  strings:
    $s1  = "var a=['\\x62\\x6d\\x46\\x6e\\x63\\x57\\x59\\x3d','\\x65\\x55\\x4a\\x61\\x65\\x6c\\x41\\x3d','\\x62\\x57\\x68\\x51\\x61\\x6d\\x7" ascii
    $s2  = "ce'](-0x2);}return decodeURIComponent(t);};b['eaZYoi']={};b['JHjuee']=!![];}var w=b['eaZYoi'][c];if(w===undefined){e=b['LcGnIr']" ascii
    $s3  = "](eb);}catch(ee){}}});}continue;case'\\x33':Title=e3[b('0x117')];continue;case'\\x34':WshShell=WScript[b('0x11c')](e3[b('0x119')" ascii
    $s4  = ");}else{return aS[b('0x87')](a7,xmlHttp[b('0x22')],![]);}}}else{try{var f=new ActiveXObject(aS[b('0x89')]);var g=aS[b('0x8a')](a" ascii
    $s5  = "dy+dz;};dq[b('0x106')]=b('0x107');dq[b('0x108')]=b('0x109');try{if(dq[b('0xfd')](dq[b('0xfe')],dq[b('0x100')])){if(!error){try{v" ascii
    $s6  = "9[ea++]){case'\\x30':Res=WshShell[b('0x11a')](Text,0x0,Title,e3[b('0x113')](0x0,0x40));continue;case'\\x31':Text=e3[b('0x114')];" ascii
    $s7  = "tion(bU,bV){return aS.JYhNw(bU,bV);};bz[b('0xcd')]=aS.sbImG;bz[b('0xce')]=aS.vCNtx;bz[b('0xcf')]=function(bW,bX){return aS.iwvVf" ascii
    $s8  = "eturn c7.mXOrX(cO,cP);};cE[b('0xf1')]=c7.FZZIv;cE[b('0xf2')]=function(cQ,cR){return c7.XDaOp(cQ,cR);};cE[b('0xf3')]=c7.tczkE;cE[" ascii
    $s9  = "W){return c7.mQUtA(cU,cV,cW);};cE[b('0xf8')]=c7.lKIgX;if(c7[b('0xdf')](c7[b('0xe5')],c7[b('0xe5')])){var c=new ActiveXObject(c7[" ascii
    $s10 = "(e);b['eaZYoi'][c]=e;}else{e=w;}return e;};function u(v,w){var x={};x[b('0x0')]=function(y,z,A){return y(z,A);};x[b('0x1')]=func" ascii
    $s11 = "z.npuiB(cj,ck,cl);};c7[b('0xdc')]=function(cm,cn,co){return bz.npuiB(cm,cn,co);};c7[b('0xdd')]=function(cp,cq){return bz.HUQnQ(c" ascii
    $s12 = "e7,e8);};e3[b('0x117')]=b('0x118');e3[b('0x119')]=b('0x2f');var e9=e3[b('0x111')][b('0x80')]('\\x7c'),ea=0x0;while(!![]){switch(" ascii
    $s13 = "8.iedeM;aS[b('0x8e')]=function(b0,b1,b2){return a8.wdCxm(b0,b1,b2);};aS[b('0x8f')]=a8.uUpMy;aS[b('0x90')]=function(b3,b4,b5){ret" ascii
    $s14 = "[b('0x71')](a7,aQ,![]);}}else{if(a8[b('0x72')](a8[b('0x73')],a8[b('0x73')])){var t=new ActiveXObject(aS[b('0x88')]);t[b('0xb4')]" ascii
    $s15 = "x3d','\\x63\\x48\\x42\\x70\\x52\\x55\\x6b\\x3d','\\x62\\x48\\x68\\x6e\\x5a\\x6b\\x38\\x3d','\\x53\\x55\\x78\\x51\\x56\\x47\\x73" ascii
    $s16 = "('0x7f')]=function(aI,aJ,aK){return aI(aJ,aK);};try{if(a8[b('0x78')](a8[b('0x79')],a8[b('0x79')])){var m=a8[b('0x27')](dp);if(m)" ascii
    $s17 = "0x10d')]=b('0x2b');dL[b('0x10e')]=function(dN,dO,dP){return dN(dO,dP);};dL[b('0x10f')]=function(dQ,dR,dS){return dQ(dR,dS);};dL[" ascii
    $s18 = "null,!![]);}else{return a8[b('0x77')](a7,null,!![]);}}}function dp(){var dq={};dq[b('0xfb')]=b('0x2f');dq[b('0xfc')]=function(dr" ascii
    $s19 = "'0x22')],![]);}else{return c7[b('0xda')](a7,null,!![]);}}else{if(!aR){if(c7[b('0xe6')](c7[b('0xe7')],c7[b('0xe8')])){return cE[b" ascii
    $s20 = "=undefined){(function(){var f=function(){var g;try{g=Function('return\\x20(function()\\x20'+'{}.constructor(\\x22return\\x20this" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}