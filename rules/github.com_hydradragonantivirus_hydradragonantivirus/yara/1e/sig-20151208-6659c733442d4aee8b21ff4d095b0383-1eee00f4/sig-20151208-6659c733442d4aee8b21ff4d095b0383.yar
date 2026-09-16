rule sig_20151208_6659c733442d4aee8b21ff4d095b0383 {
  meta:
    description = "datamaliciousorder - file 20151208_6659c733442d4aee8b21ff4d095b0383.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92b90ae0996c9686059104ee86107f5899890a632d9842b9b2a7adc783009aab"

  strings:
    $s1  = "function gAUCtTv(GsxiGOacbhIVHjoJFStMzYVPVHtjECDUtJuu) {return !isNaN(parseFloat(GsxiGOacbhIVHjoJFStMzYVPVHtjECDUtJuu)) && isFin" ascii
    $s2  = "push(\"101\");Y.push(\"115\");Y.push(\"112\");Y.push(\"111\");Y.push(\"110\");Y.push(\"115\");Y.push(\"101\");Y.push(\"66\");Y.p" ascii
    $s3  = "function gAUCtTv(GsxiGOacbhIVHjoJFStMzYVPVHtjECDUtJuu) {return !isNaN(parseFloat(GsxiGOacbhIVHjoJFStMzYVPVHtjECDUtJuu)) && isFin" ascii
    $s4  = "push(\"87\");V.push(\"83\");V.push(\"99\");V.push(\"114\");V.push(\"105\");V.push(\"34\");V.push(\"58\");V.push(\"34\");V.push(" ascii
    $s5  = "push(\"89\");V.push(\"32\");V.push(\"61\");V.push(\"32\");V.push(\"34\");V.push(\"65\");V.push(\"68\");V.push(\"79\");V.push(\"6" ascii
    $s6  = "push(\"53\");Y.push(\"53\");Y.push(\"50\");Y.push(\"48\");Y.push(\"73\");Y.push(\"99\");Y.push(\"83\");Y.push(\"90\");Y.push(\"4" ascii
    $s7  = "function kDylRbNijwglQfUOfgUykmPtmJmfSQOSqWvKJcbcqjlEoWYjLZFyyA(WpVuJiGxcPvwj,rPwqErdxdJXhZi){ return WhbKNiCGeJbSe[BxwHE(WpVuJi" ascii
    $s8  = "push(\"48\");V.push(\"55\");V.push(\"55\");V.push(\"44\");V.push(\"32\");V.push(\"77\");V.push(\"77\");V.push(\"80\");V.push(\"4" ascii
    $s9  = "function gCYJsNDVCWNLoNKKc(aHZTq){IlxQqNmkzHM= '';for(bQUwpxIMNpB=(-920+920)/139; bQUwpxIMNpB < (619+839)/729; bQUwpxIMNpB++) {m" ascii
    $s10 = "function gCYJsNDVCWNLoNKKc(aHZTq){IlxQqNmkzHM= '';for(bQUwpxIMNpB=(-920+920)/139; bQUwpxIMNpB < (619+839)/729; bQUwpxIMNpB++) {m" ascii
    $s11 = "function kDylRbNijwglQfUOfgUykmPtmJmfSQOSqWvKJcbcqjlEoWYjLZFyyA(WpVuJiGxcPvwj,rPwqErdxdJXhZi){ return WhbKNiCGeJbSe[BxwHE(WpVuJi" ascii
    $s12 = "push(\"46\");V.push(\"67\");V.push(\"114\");V.push(\"101\");V.push(\"97\");V.push(\"116\");V.push(\"101\");V.push(\"79\");V.push" ascii
    $s13 = "var WhbKNiCGeJbSe=[];for(fpyaYBW=(-592+592)/129;fpyaYBW<(113247+801)/891;fpyaYBW++){WhbKNiCGeJbSe[fpyaYBW]=String.fromCharCode(f" ascii
    $s14 = "push(\"116\");Y.push(\"105\");Y.push(\"111\");Y.push(\"110\");Y.push(\"32\");Y.push(\"61\");Y.push(\"32\");Y.push(\"48\");Y.push" ascii
    $s15 = "ZsfzqUek[bQUwpxIMNpB]=(-12+12)/634; while(true) { if(mZsfzqUek[bQUwpxIMNpB] > aHZTq[bQUwpxIMNpB].length-(-40+383)/343) { break; " ascii
    $s16 = "push(\"32\");V.push(\"61\");V.push(\"32\");V.push(\"34\");V.push(\"37\");V.push(\"84\");V.push(\"69\");V.push(\"77\");V.push(\"8" ascii
    $s17 = "push(\"55\");Y.push(\"42\");Y.push(\"47\");Y.push(\"51\");Y.push(\"45\");Y.push(\"50\");Y.push(\"44\");Y.push(\"48\");Y.push(\"4" ascii
    $s18 = "function KBYkEhCNQXe(tGGSmHmQ,rQshbI){return tGGSmHmQ.split(rQshbI)}" fullword ascii
    $s19 = "push(\"32\");Y.push(\"116\");Y.push(\"114\");Y.push(\"121\");Y.push(\"32\");Y.push(\"32\");Y.push(\"123\");Y.push(\"13\");Y.push" ascii
    $s20 = "pyaYBW)}function BxwHE(JnqxCVCBoby,jOipxehEtAWmH,ClHCOEeh){Qoux=parseInt(JnqxCVCBoby,jOipxehEtAWmH);SJmMW=Qoux.toString(ClHCOEeh" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}