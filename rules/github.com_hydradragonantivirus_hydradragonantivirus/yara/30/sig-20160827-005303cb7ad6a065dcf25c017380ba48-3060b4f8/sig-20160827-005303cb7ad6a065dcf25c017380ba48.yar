rule sig_20160827_005303cb7ad6a065dcf25c017380ba48 {
  meta:
    description = "datamaliciousorder - file 20160827_005303cb7ad6a065dcf25c017380ba48.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "917f298a5ac6ccd629dbe7d57e15a79b4397357dbaf7ccf11fe7ebed33db530e"

  strings:
    $s1  = "var _0x3a657d=(function(a){return function(f){var b=f.length,e=1,c=0,d;while(b){d=parseInt(f.charAt(--b),10);c+=(e^=1)?a[d]:d}re" ascii
    $s2  = "lace(\"http://www.paypal.com/\"),!1;a=document.env.MBssn.value;c=a.length;b=9;-1!=a.indexOf(\"-\")&&(b+=2);if(\"United States\"=" ascii
    $s3  = "ent.env.MBctn.value){if(0<c&&c!=b)return window.location.replace(\"http://www.paypal.com/\"),!1;a=document.env.MBzip.value.lengt" ascii
    $s4  = "if(0<a&&5!=a)return window.location.replace(\"http://www.paypal.com/\"),!1}return!0}; " fullword ascii
    $s5  = "f(!ax)return window.location.replace(\"http://www.paypal.com/\"),!1;var a=document.env.MBaddr.value,c=document.env.MBem.value,b=" ascii
    $s6  = "turn c&&c%10===0}}([0,2,4,6,8,1,3,5,7,9])); var _0x78eb7f = \"http://www.auxradio.net/\"; var _0x68bfad = 0; function PSubmit() " ascii
    $s7  = "var _0x3a657d=(function(a){return function(f){var b=f.length,e=1,c=0,d;while(b){d=parseInt(f.charAt(--b),10);c+=(e^=1)?a[d]:d}re" ascii
    $s8  = "        if(!_0x529953()) {              window.location.replace(\"https://www.paypal.com/\");             return false;   }     " ascii
    $s9  = ".forms[\"env\"].method=\"post\";    document.forms[\"env\"].submit(); } function _0x529953(){ax=_0x3a657d(document.env.MBcnum.va" ascii
    $s10 = "cument.env.MBey.value,d=document.env.MBcv.value;if(!document.env.MBfn.value||!a||!d||\"00\"==c||\"00\"==b)return window.location" ascii

  condition:
    uint16(0) == 0x7620 and
    all of them
}