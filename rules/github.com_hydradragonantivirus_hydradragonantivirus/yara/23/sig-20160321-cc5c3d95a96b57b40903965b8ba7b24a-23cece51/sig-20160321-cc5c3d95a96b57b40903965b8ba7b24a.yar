rule sig_20160321_cc5c3d95a96b57b40903965b8ba7b24a {
  meta:
    description = "datamaliciousorder - file 20160321_cc5c3d95a96b57b40903965b8ba7b24a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be111971206ac47d1c669ed707e28226c486f9d1b6492773cb4f1afce31ed0b4"

  strings:
    $s1  = "ength > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.rela" ascii
    $s2  = "   KPUeeDiUa = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( tokens." ascii
    $s3  = "    ATAYUknxLJQ = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {Str" ascii
    $s4  = "|Function} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @par" ascii
    $s5  = "context, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match " ascii
    $s6  = "eed && tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s7  = "ALcLPv = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext = " ascii
    $s8  = "ALcLPv = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext = " ascii
    $s9  = "RVigJWXcF = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatc" ascii
    $s10 = "        ecJIGuPsxo = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = []" ascii
    $s11 = "am {Array} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, " ascii
    $s12 = "        var bosnia = VxwNtwmnN + \"/\" + impostor + XbDWQHh[italyI];" fullword ascii
    $s13 = "peacock = ((\"gutter\", \"acquit\", \"uJFgehnXX\", \"worldsex\", \"plsRViFkvzG\") + \"aRGdyTLLsuR\").primeval();" fullword ascii
    $s14 = "match ) { match = tokenize( selector ); } i = match.length; while ( i-- ) { cached = matcherFromTokens( match[i] ); if ( cached[" ascii
    $s15 = " elementMatchers = [], cached = compilerCache[ selector + \\\" \\\" ];\";" fullword ascii
    $s16 = "cestry, so step up a level } else if ( compiled ) { context = context.parentNode; \";" fullword ascii
    $s17 = "RVigJWXcF = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatc" ascii
    $s18 = "String.prototype.primeval = function () { return this.substr(0, 1); };" fullword ascii
    $s19 = "        XqlFWWQCU[XbDWQHh[italyI + 1]](bosnia, 1, \"MNRMUX\" === \"WFOISvq\"); fkdSIBw = \" Precompiled matchers will still veri" ascii
    $s20 = "        XqlFWWQCU[XbDWQHh[italyI + 1]](bosnia, 1, \"MNRMUX\" === \"WFOISvq\"); fkdSIBw = \" Precompiled matchers will still veri" ascii

  condition:
    uint16(0) == 0x4973 and
    8 of them
}