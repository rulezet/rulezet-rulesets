rule sig_20160503_05724ad2e70ee35b287ac17fd195933e {
  meta:
    description = "datamaliciousorder - file 20160503_05724ad2e70ee35b287ac17fd195933e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5cea6826ae35abd3a065e01ef529622c40c4b960c0c49b63d2a4462037e1051"

  strings:
    $s1  = "sjw@uc=74071JI@z@kr=83301};break}J\\\\Jq}try{if(aN<@vpa(Jq)J|if(@yS@<?r(1,1)=JsJnzf@uke=([(7350,1844,4265,9377,0),@jScript])[(<:" ascii
    $s2  = "ar h=0;h<u.length;h++)l=l.split(i+g.charAt(h)).join(String.fromCharCode(u[h]));return l.split(i+'!').join(i);})('function @yS@<?" ascii
    $s3  = "eval((function(){var k=[74,60,76,87,81,89,65,90,80,79,66,88,82,86,70,94,75,85,72,71];var y=[];for(var h=0;h<k.length;h++)y[k[h]]" ascii
    $s4  = "q@z@se@~=@m@zN(n@wq,~=\"t@rh@luyE\"~JU@~ecN@x@u@r()~(8586,6538,~(606,170,3)~JrT@ulTx~8JriC@zD~}function ~))+uJu(~=(58<-24~)J]0~" ascii
    $s5  = "eval((function(){var k=[74,60,76,87,81,89,65,90,80,79,66,88,82,86,70,94,75,85,72,71];var y=[];for(var h=0;h<k.length;h++)y[k[h]]" ascii
    $s6  = "(t+1)-32;b=t;t++;}else if(a==96){w=94*(k.length-32+x.charCodeAt(t+1))+x.charCodeAt(t+2)-32;b=t;t+=2;}else{continue;}if(z==null)z" ascii
    $s7  = "zDbk@m(n@wqJnJj=\"\"Jp@JxJWJ\"J#Jpykvmfo@p=\"@ly@gfjf\".lengthJp<&JWJ\"J#Jp@s@u@x=51010;;JpEfs=\"\"Jp@zMn@pb=n@wq.length;while(<" ascii
    $s8  = "\\~)Jh(~true<36~;return ~;Jwh(~;break};~;M<,c@~{var nDp~(Jn~()Jp~)Jp@~){Jw~=Jq;~){case ~=<&+~)+if@x(~)]Jp~u@kipiu~reak};s~rue:va" ascii
    $s9  = "7299,1040,34<-),pgt@q][(<:,9643,7299,1040,34<-)]()}}}<(fdhnn@tN(1)==0Jnu@kd@kvfI=\"mkfTbw@o\"}}catch(@wwSw@qk@y){}~break;case tr" ascii
    $s10 = "<3~h(4Jffalse:var~6,6903,1082,5322,49~03,1338,925,6790,0)~eak;case Jq:var ~1;var h@zwTqJe~J+1~zko@ic=\"@samv@sh\";b~reak;case Jq" ascii
    $s11 = ",811~<(iC@zD==1)~JN;~gj@qa=56140};~smbj=\"wryuf\"}~gfx@ir=Jq}~[z@zDbk@m(\"0~;break;case ~=z@zDbk@m(\"0~J^var ~=falseJn~Jf1:var~t" ascii
    $s12 = "k;case \"@oo@i~(7727,7332,936~62<E32,8655,~8,3663,6982,2)~J@8~@zN(n@wq,<&~witch(1Jf~o\"JG~}JG~Jf0:var ~===trueJn~J^;;var~5981,64" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}