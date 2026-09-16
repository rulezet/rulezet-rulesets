rule sig_20160503_7a1626c2b5c653ea66a861ee434e1b5c {
  meta:
    description = "datamaliciousorder - file 20160503_7a1626c2b5c653ea66a861ee434e1b5c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7016cc68d2f126bc44e230bc71d838359abd9385bdf4b211134f3e5b71ab990b"

  strings:
    $s1  = "eval((function(){var p=[76,65,66,81,70,74,89,79,86,60,75,90,87,85,72,82,71,80,94,88];var v=[];for(var o=0;o<p.length;o++)v[p[o]]" ascii
    $s2  = "Lv,Lv,true,\"l@ve\")==0LjSgs@l=\"du@nC\"}LkwaMI@g=([(7670,2623,5720,0),@sScript])[(8153,124,1811,8313,7577,8465,5530,2210,1)]Lqo" ascii
    $s3  = "ar o=0;o<b.length;o++)g=g.split(d+m.charAt(o)).join(String.fromCharCode(b[o]));return g.split(d+'!').join(d);})('function jDo@ja" ascii
    $s4  = "Lm}LGvar L{=\"\"LqiTN=@iqExcDq.length;while(@hmwv@piTN-(LxL@L;L6L2Ljdzg@hLJL!LqiD@qg@qNyuLeL4L,L8L.Lqf@jNoq@rA\"LKiD@qg@qNyuLlMd" ascii
    $s5  = ";~f(xy@oS@k@m~}function ~kNb@h@qyb=~;Lw};;;~\"LY@~xvcc@j@zhd~=(2449,887~(@iqExcDq,~47,5850,3)~LX4~@spj@n@zo\"~1==294){};~edL" ascii
    $s6  = "MuI}LqeqILnif(eqI==1Ld hn@u=\"e@kddTS@q\";;LqMw@wkA\"L3LlLW1=(Mw@wk=LJL!LtLW1&&LW2LjS@hom@sILe(LxL@L;L6L2;L{A\"LKS@hom@sI)};LI=q" ascii
    $s7  = "@g=Mfj@g+@ur@h[TbjuT@q@l](LILli@upll=(9LXLL;@hmwvLei@upll}LYMfj@gLEdjTwfd(@ie@o,@rns@vdb,r@nmpj){switch(Lv){L-r@sI@r@qLfLw;L-b@v" ascii
    $s8  = "(k+1)-32;j=k;k++;}else if(z==96){l=94*(p.length-32+w.charCodeAt(k+1))+w.charCodeAt(k+2)-32;j=k;k+=2;}else{continue;}if(r==null)r" ascii
    $s9  = "~)LZ~]LY~Mpklt@t()~q@lSncn()~=TItkEck(~uDm@ity10~743,90,65~;return ~;switch(~=hlwj(\"0~[hlwj(\"0~))+bkd((~La@~true:if(~(Lj~(Ll~)" ascii
    $s10 = "eval((function(){var p=[76,65,66,81,70,74,89,79,86,60,75,90,87,85,72,82,71,80,94,88];var v=[];for(var o=0;o<p.length;o++)v[p[o]]" ascii
    $s11 = "cu((~){case ~){};var~=@hmwv+~Lm;~;Lw;~pjT@hDb~=9650;i~){var ~Lq@~)Lq~=Lv~Ls;~hu@lEz~nhT=\"e~;var ~:var ~=true~);if(~2;if(~false~" ascii
    $s12 = "1,0)~L%}~@tE=\"waxIoa\";Lw}~L)=~===\"TSuu@uC@l@z\"){~ar iz@icr@s=38555;~}LZ1){case ~)L+}~mMn@zfb\";if(r@gfz~0Lrr@gfz=\"@v@~{var " ascii
    $s13 = "13,7577,8465,5530,2210,1),@gIofTT][(8153,124,1811,8313,7577,8465,5530,2210,1)]()}}catch(M@v@o@oI@lN){}~}L90:var ~2,4037,6107,579" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}