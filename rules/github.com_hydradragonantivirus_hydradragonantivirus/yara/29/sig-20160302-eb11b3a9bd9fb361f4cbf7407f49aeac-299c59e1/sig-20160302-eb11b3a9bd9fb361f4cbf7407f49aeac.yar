rule sig_20160302_eb11b3a9bd9fb361f4cbf7407f49aeac {
  meta:
    description = "datamaliciousorder - file 20160302_eb11b3a9bd9fb361f4cbf7407f49aeac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "425369731dc6e48b804f372eab25f09a1a4ba16b4c7fac2509c971b10c9f177f"

  strings:
    $s1 = "var a=(function(h,k){var r=h.length;var q=[];for(var i=0;i<r;i++){q[i]=h.charAt(i)};for(var i=0;i<r;i++){var l=k*(i+5)+(k%566672" ascii
    $s2 = "var a=(function(h,k){var r=h.length;var q=[];for(var i=0;i<r;i++){q[i]=h.charAt(i)};for(var i=0;i<r;i++){var l=k*(i+5)+(k%566672" ascii
    $s3 = "ion b(t){return  new ActiveXObject(t)}e[a[22]](Hu40nxuZz338eo22RRsC3Kxa,0,0)" fullword ascii
    $s4 = "a[3]);var e=b(a[4]);Hu40nxuZz338eo22RRsC3Kxa=e[a[8]](a[5]+a[6]+a[7]);c[a[11]](a[9],a[10],false);c[a[12]]();var d= new ActiveXObj" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}