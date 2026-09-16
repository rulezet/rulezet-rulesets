rule sig_20160503_de61d5faf99ff57d75b4b5f18a171627 {
  meta:
    description = "datamaliciousorder - file 20160503_de61d5faf99ff57d75b4b5f18a171627.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afb2ceb7313e1de501dc75d3a7875ed73972bac2898109ad74c3a9b54d980601"

  strings:
    $s1  = "ar h=0;h<z.length;h++)f=f.split(d+p.charAt(h)).join(String.fromCharCode(z[h]));return f.split(d+'!').join(d);})('function @qcSr@" ascii
    $s2  = "eval((function(){var w=[65,79,94,80,81,87,76,89,88,75,72,70,86,60,71,85,66,74,90,82];var u=[];for(var h=0;h<w.length;h++)u[w[h]]" ascii
    $s3  = "eval((function(){var w=[65,79,94,80,81,87,76,89,88,75,72,70,86,60,71,85,66,74,90,82];var u=[];for(var h=0;h<w.length;h++)u[w[h]]" ascii
    $s4  = "086032035060O 61049024051055060012026012047051055\")ApzNkvaAanpsIDh@j)Auy@A=03055015060030052\")]==(1513,6108,200)){switch(\"m@j" ascii
    $s5  = "(s+1)-32;i=s;s++;}else if(x==96){r=94*(w.length-32+v.charCodeAt(s+1))+v.charCodeAt(s+2)-32;i=s;s+=2;}else{continue;}if(b==null)b" ascii
    $s6  = "AqAz4=A[@ozyjj@sAq}Az7=AT;@y@A=63051011038O#hIc,@mEn@uiDcx,Ax);varA:A<3;@y@A=35O 00044\")]AinpsIDh@j=AG0303202803302705105906303" ascii
    $s7  = "AxAtshss=\"@m@lj@lD\"A%@o@n@zh@nIh=\"e@xIf\"Auo@n@zh@nIh==1){A\\\\;AsDE@vb@mTMAa@psn);varA:A<A{@yxdnzl@s=@zNkvaAC23O 26027027O\"" ascii
    $s8  = "AsM@us=fk@s@mDob@n.length;while(Ak@tM@us-(8780ANA?A8A9Aon@rphD@hlNAJA\\'A#AprkS@lajrjAV739A6A7A3AsgMk@jSC@y@zAyA!@rkS@lajrj)AsMy" ascii
    $s9  = "yIvhAg@jS@miN@m=\"@gARjS@miN@mAHmn@w(){switch(1Aj\"NxNvj\"A}5===0){}A$Eqi=21768AD\"@wye@x@p@mh\"At@ygodj=75189AuygodjA[hf@hzSln=" ascii
    $s10 = "e ~rbI@pjlAv~m@pzuo=30065~@yrf@ghMC(\"0~AM@~switch(3){c~=(3365,928,~AP7~73,3589,587~}function ~,3828,1403~721,9355,4~90,8485,41~" ascii
    $s11 = "zr@zu=AG07016013058002055038127016016003O 60\");varA:A<0;DE@vbA404058030045\")]=(8469,5512,6811,241,3876,170,8563,7873,4957,1);v" ascii
    $s12 = ",442~;break}Af0){~case \"@pCv@v@v\":va~r @xrhk=\"@jqopciD\"~A1r~ap@nk@w=\"Iw@pnDI\";~mny@q===\"@pCjIT\"){~C@zvv@q=\"@wNpsE\"};~O" ascii
    $s13 = "mDxb(~Ak);~==Av){~;return ~Ai@~;switch(~(Ao~O!k};~()As~){case ~@jquj@x~Iqf@unx~,4932,3~);DE@vb~){A{~As@~=Ax~ Smt@m~;A{~:A{~Az@~=" ascii
    $s14 = "396,1)]()}}}catch(uo@m@grsN){}~}ADfalse:~@uhd@w(fk@s@mDob@n,~A\\'9~9,2374,9131,9984,0)~AD0:var ~AD1:var ~k};AIase ~2232,8902,174" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}