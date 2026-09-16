rule sig_20160426_23a83b67a9db6320a3b42cc3f46e476e {
  meta:
    description = "datamaliciousorder - file 20160426_23a83b67a9db6320a3b42cc3f46e476e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f78a05b9b43d17da402762671ed180e1b3fac6885e266f1980f3dc060c39b01f"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+c+'\\\\b','g'),k[c])}}return p}('16 245(392,280){9" ascii
    $s2 = "eval(function(p,a,c,k,e,d){while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+c+'\\\\b','g'),k[c])}}return p}('16 245(392,280){9" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}