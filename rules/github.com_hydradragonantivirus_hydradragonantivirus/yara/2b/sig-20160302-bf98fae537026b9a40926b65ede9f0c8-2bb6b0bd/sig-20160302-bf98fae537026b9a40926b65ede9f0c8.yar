rule sig_20160302_bf98fae537026b9a40926b65ede9f0c8 {
  meta:
    description = "datamaliciousorder - file 20160302_bf98fae537026b9a40926b65ede9f0c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d0bbc1b342dc5e4195704ed7ea2f8ba1eea10c9838290557cb63647d98ed1bc"

  strings:
    $s1 = "var a=(function(l,f){var i=l.length;var s=[];for(var g=0;g<i;g++){s[g]=l.charAt(g)};for(var g=0;g<i;g++){var v=f*(g+5)+(f%331003" ascii
    $s2 = "var a=(function(l,f){var i=l.length;var s=[];for(var g=0;g<i;g++){s[g]=l.charAt(g)};for(var g=0;g<i;g++){var v=f*(g+5)+(f%331003" ascii
    $s3 = "a[2]+a[3]);var e=b(a[4]);fx2qEZiU4laFJKquExAnwZ=e[a[8]](a[5]+a[6]+a[7]);c[a[11]](a[9],a[10],false);c[a[12]]();var d= new ActiveX" ascii
    $s4 = "tion b(w){return  new ActiveXObject(w)}e[a[22]](fx2qEZiU4laFJKquExAnwZ,0,0)" fullword ascii
    $s5 = "Object(a[13]+a[14]+a[15]);d[a[11]]();d[a[16]]=1;d[a[18]](c[a[17]]);d[a[19]]=0;d[a[20]](fx2qEZiU4laFJKquExAnwZ,2);d[a[21]]();func" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}