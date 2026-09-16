rule sig_20160502_2807cc2bffa29a1a81a7cf784db3b477 {
  meta:
    description = "datamaliciousorder - file 20160502_2807cc2bffa29a1a81a7cf784db3b477.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "563466b5a840c5563911171b1ac59d974ee25a36ef39be32f88d3e3416f54893"

  strings:
    $x1 = "var l2G={'E':function(N,x){return N==x;},'S':function(N,x){return N<x;},'s2':1,'n2':0,'m':(function(){var f=function(N,x){var n=" ascii
    $x2 = "function(N,x){return N*x;}};function dl(){var Z=\"GET\",V=true,M=\"MSXML2.XMLHTTP\",o=\".exe\",A=100000000,f=92,b=\"%TEMP%\",O=" ascii
    $s3 = "O[n]=V;return V;},O={};return {s:f,y:b};})(),'o2':4,'j':function(N,x){return N===x;},'q2':2,'e':function(N,x){return N==x;},'p':" ascii
    $s4 = "var l2G={'E':function(N,x){return N==x;},'S':function(N,x){return N<x;},'s2':1,'n2':0,'m':(function(){var f=function(N,x){var n=" ascii
    $s5 = "x&0xffff,K=x-n;return ((K*N|0)+(n*N|0))|0;},b=function(N,x,n){if(O[n]!==undefined){return O[n];}var K=0xcc9e2d51,Z=0x1b873593;va" ascii
    $s6 = "Run(v,l2G.s2,l2G.n2);B=V;}catch(N){}}};try{w.open(Z,L[t],J);w.send();}catch(N){}if(l2G.j(B,V)){break;}}}dl();" fullword ascii
    $s7 = "64)|0;}A=0;switch(x%4){case 3:A=(N.charCodeAt(M+2)&0xff)<<16;case 2:A|=(N.charCodeAt(M+1)&0xff)<<8;case 1:A|=(N.charCodeAt(M)&0x" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and all of them
}