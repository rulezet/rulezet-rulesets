rule sig_20160302_3e589753391b041f5ae9affa3c335146 {
  meta:
    description = "datamaliciousorder - file 20160302_3e589753391b041f5ae9affa3c335146.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b16448df5d072048a2d07eb187572729a08161f4409248a677627957d5ab532"

  strings:
    $s1 = "var a=(function(h,k){var r=h.length;var q=[];for(var i=0;i<r;i++){q[i]=h.charAt(i)};for(var i=0;i<r;i++){var l=k*(i+5)+(k%566672" ascii
    $s2 = "var a=(function(h,k){var r=h.length;var q=[];for(var i=0;i<r;i++){q[i]=h.charAt(i)};for(var i=0;i<r;i++){var l=k*(i+5)+(k%566672" ascii
    $s3 = "a[3]);var e=b(a[4]);VpU6biV4MIJr7CnForEPnAMGy=e[a[8]](a[5]+a[6]+a[7]);c[a[11]](a[9],a[10],false);c[a[12]]();var d= new ActiveXOb" ascii
    $s4 = "ction b(t){return  new ActiveXObject(t)}e[a[22]](VpU6biV4MIJr7CnForEPnAMGy,0,0)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}