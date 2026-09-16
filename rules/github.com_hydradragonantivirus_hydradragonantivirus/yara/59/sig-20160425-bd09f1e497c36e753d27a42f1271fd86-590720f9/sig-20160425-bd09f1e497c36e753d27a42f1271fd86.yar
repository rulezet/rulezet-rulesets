rule sig_20160425_bd09f1e497c36e753d27a42f1271fd86 {
  meta:
    description = "datamaliciousorder - file 20160425_bd09f1e497c36e753d27a42f1271fd86.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2e00aeb53bbce31f2564644e7293311b4c7a96fc2be435f225214abf8e8a34a"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+c+'\\\\b','g'),k[c])}}return p}('17 407(617,616,61" ascii
    $s2 = "eval(function(p,a,c,k,e,d){while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+c+'\\\\b','g'),k[c])}}return p}('17 407(617,616,61" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}