rule sig_20151209_43222b20c289127b89991abc2af03f67 {
  meta:
    description = "datamaliciousorder - file 20151209_43222b20c289127b89991abc2af03f67.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e64effda4dfe8e316da1f8962b4f98f57a76772eae0634823d3360f9e20cce4"

  strings:
    $s1  = "function BSyBOdu(mhQpzFXUdUhjRUpItTRbBvWiRjUjJgeiUyjZ) {return !isNaN(parseFloat(mhQpzFXUdUhjRUpItTRbBvWiRjUjJgeiUyjZ)) && isFin" ascii
    $s2  = "function BSyBOdu(mhQpzFXUdUhjRUpItTRbBvWiRjUjJgeiUyjZ) {return !isNaN(parseFloat(mhQpzFXUdUhjRUpItTRbBvWiRjUjJgeiUyjZ)) && isFin" ascii
    $s3  = "function DMDfr(basFkeqWGiL,ReoumMJRUADAe,ENHZqMKo){ekHD=parseInt(basFkeqWGiL,ReoumMJRUADAe);Fotbd=ekHD.toString(ENHZqMKo);return" ascii
    $s4  = "function bjHKppDEKYoajWJDKUwGlWDeYpqVvAhFEeTBNOTvHihlsCFdYjecoS(tsSfioHVORrRC,khNNBHIYFxJgoN){ return pcccE[DMDfr(tsSfioHVORrRC[" ascii
    $s5  = "} return CHjiskgXvXV}" fullword ascii
    $s6  = "function DMDfr(basFkeqWGiL,ReoumMJRUADAe,ENHZqMKo){ekHD=parseInt(basFkeqWGiL,ReoumMJRUADAe);Fotbd=ekHD.toString(ENHZqMKo);return" ascii
    $s7  = " Fotbd;}function KwvZnMrACxUwjTb(dgEcetNTVLFDajMyF){eval(dgEcetNTVLFDajMyF)}" fullword ascii
    $s8  = "function bjHKppDEKYoajWJDKUwGlWDeYpqVvAhFEeTBNOTvHihlsCFdYjecoS(tsSfioHVORrRC,khNNBHIYFxJgoN){ return pcccE[DMDfr(tsSfioHVORrRC[" ascii
    $s9  = "function haksYvtVvUHlOINPP(dkMpC){CHjiskgXvXV= '';for(FguylUHNlZe=(-322+322)/673; FguylUHNlZe < (749+455)/602; FguylUHNlZe++) {j" ascii
    $s10 = "function IBoPuTSuePh(SFxOOzjU,UcjGVc){return SFxOOzjU.split(UcjGVc)}" fullword ascii
    $s11 = "function haksYvtVvUHlOINPP(dkMpC){CHjiskgXvXV= '';for(FguylUHNlZe=(-322+322)/673; FguylUHNlZe < (749+455)/602; FguylUHNlZe++) {j" ascii
    $s12 = "tUpbRrLj[FguylUHNlZe]=(-524+524)/94; while(true) { if(jtUpbRrLj[FguylUHNlZe] > dkMpC[FguylUHNlZe].length-(673+183)/856) { break;" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}