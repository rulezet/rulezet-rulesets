rule sig_20160503_16bc21eb2f71db41174c418d34d15afa {
  meta:
    description = "datamaliciousorder - file 20160503_16bc21eb2f71db41174c418d34d15afa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff521ef69dcfb021708d447b3e2e38a5b934c29f712e5a4b2ab14d45d682b642"

  strings:
    $s1  = "@q@l@p@hx(239,\"y@vC@sM@n@rd\",230,1)!=1BhmMD@gi@qBk}else {P$cDdS=([(830,4673,5643,1299,0),@iScript])[(6403,9P,1)]BiiSqNu@xzf=cD" ascii
    $s2  = "ar c=0;c<d.length;c++)y=y.split(n+p.charAt(c)).join(String.fromCharCode(d[c]));return y.split(n+'!').join(n);})('function gDfg@v" ascii
    $s3  = "eval((function(){var k=[66,80,87,72,94,76,86,75,89,71,85,88,65,74,70,81,79,82,90,60];var o=[];for(var c=0;c<k.length;c++)o[k[c]]" ascii
    $s4  = "(i+1)-32;u=i;i++;}else if(z==96){w=94*(k.length-32+r.charCodeAt(i+1))+r.charCodeAt(i+2)-32;u=i;i+=2;}else{continue;}if(f==null)f" ascii
    $s5  = "rSl@u=BkB5P)P\\'yi@rEs=B^BvsC@hjoy=\"@ljfMh@o\"};break}BYP)BLifeB`yMj@rqT=[(5295,2169,6629,817,812,314,3025,8015,7651,7773,1),@s" ascii
    $s6  = "\"@gCme\"B[BvynvEvpv=928P#@ynvEvpvBU}BYtrue}try{if(gDfg@vn@s(true,\"wqc\",1)BUP$mMD@gi@qBk}P#@mnCgam(504,\"@l@x@l@mow\",By,107)B" ascii
    $s7  = "eval((function(){var k=[66,80,87,72,94,76,86,75,89,71,85,88,65,74,70,81,79,82,90,60];var o=[];for(var c=0;c<k.length;c++)o[k[c]]" ascii
    $s8  = "mNj(~t@l@g@wm@x~Beif(~\"BY~=Bk){~rD@njch@q~)+@hbi@u(~)Biol~;return ~;switch(~;break};~){}Bt~{switch(~=Bu){~trueP#~(Bh@~@llxbp()~" ascii
    $s9  = "tdm@xbr~@hbi@u((~(Bj~Bk;~){case ~j@vIM@s~B{ ~Bt@~)Bt~=By~\"Bw~dsty@r~=(4003~\"P#@~,5619,~14,361~oeyu10~if(1==~;P$~=P)~P$@~:P$~)P" ascii
    $s10 = "5,5Bx@p@jeji){[(6403,9P,1),@v@gIw@g@p@l][(6403,9P,1)]()}}}}catch(y@i@rc){}~B#3~35,4171,533,1052,0)~eak;case trueBw~,8542,7077,62" ascii
    $s11 = "~;break;case ~@pTlh@l@j@y+~{case 1Bw~@i@sv@nikT()~reak};;Bt~)+BQ~pTlh@l@j@y);~BP@~)BW(~@lETnSD@q()~Ey@gSvS@u@g~}function ~jE@oh@" ascii
    $s12 = "@we@u,~058,4403,3370,658~break;case 0Bw~B18~8835,3070,3P,2)~(3562,6204,6654,~B9@~@hTI@ty@x=60932;~;break}BZ~){}BE~07,5706,6264,8" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}