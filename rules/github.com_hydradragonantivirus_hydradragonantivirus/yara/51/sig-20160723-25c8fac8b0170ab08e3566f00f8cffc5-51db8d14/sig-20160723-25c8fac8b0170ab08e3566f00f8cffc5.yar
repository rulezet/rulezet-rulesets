rule sig_20160723_25c8fac8b0170ab08e3566f00f8cffc5 {
  meta:
    description = "datamaliciousorder - file 20160723_25c8fac8b0170ab08e3566f00f8cffc5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6a8baacc95a908597be4302d3203816b98c3691cd62ab8d4b53f61ecf753ffb"

  strings:
    $s1 = "sYD=new Array((new Date().getYear()==2016) ? 'rCode(parseInt' : 'zID')[0];" fullword ascii
    $s2 = "Hkmq=new Array((new Date().getYear()==2016) ? 'turn String.from' : 'Cqn')[0];" fullword ascii
    $s3 = "G_mfF=new Array((new Date().getYear()==2016) ? 'U,16)^' : 'lGYs')[0];" fullword ascii
    $s4 = "return new Function('U', 're'+Hkmq+'Cha'+sYD+'('+G_mfF+'43)')(Hr);" fullword ascii
    $s5 = "while(sdH<y8QbS.length)" fullword ascii
    $s6 = "k=(new Function(Q22G0))(k);" fullword ascii
    $s7 = "return new Function('WCnsV', 're'+jnI+'Cha'+z0t3+'('+XKi+'77)')(R);" fullword ascii
    $s8 = "function Z9uoQ(R)" fullword ascii
    $s9 = "catch(WPw)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}