rule sig_20160422_c1bc848a76c7573f4df6cd78e333a6d5 {
  meta:
    description = "datamaliciousorder - file 20160422_c1bc848a76c7573f4df6cd78e333a6d5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c80485837cb5525e339825e3adf8e703e9a4b8339d8ea46d2edea39df1546fb"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('j 5F(){8 7H=f;8 7G=f;8 4U=f;c(4U===7F){8 7I=\"7J\"" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}