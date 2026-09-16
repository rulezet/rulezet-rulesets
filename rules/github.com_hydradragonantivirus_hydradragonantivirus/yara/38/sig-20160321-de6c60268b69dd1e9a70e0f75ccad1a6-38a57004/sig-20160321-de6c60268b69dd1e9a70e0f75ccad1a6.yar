rule sig_20160321_de6c60268b69dd1e9a70e0f75ccad1a6 {
  meta:
    description = "datamaliciousorder - file 20160321_de6c60268b69dd1e9a70e0f75ccad1a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b2a4fd5b2a78378a7a37c8b1fffb65612d65df3d8039c28df02fd4f43392e78"

  strings:
    $s1  = "th > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.relativ" ascii
    $s2  = "   ufOnml = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( tokens.len" ascii
    $s3  = "    fcVsWIMwA = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {Strin" ascii
    $s4  = "unction} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @param" ascii
    $s5  = "ntext, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match = " ascii
    $s6  = "d && tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s7  = "jqXeRQg = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext =" ascii
    $s8  = "jqXeRQg = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext =" ascii
    $s9  = "length > 0 && ( matchedCount + setMatchers.length ) > 1 ) {\";" fullword ascii
    $s10 = "QRETAk = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatched" ascii
    $s11 = "        wvYPVQalxhg = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = [" ascii
    $s12 = " {Array} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, co" ascii
    $s13 = "    fLbDbWo[\"o\" + pegasus + forgavee + \"n\"]((\"induction\",\"spaulding\",\"G\") + forgavee + (\"tricks\",\"coalesce\",\"logg" ascii
    $s14 = "String.prototype.cipher = function () { return this.substr(0, 1); };" fullword ascii
    $s15 = ", elementMatchers = [], cached = compilerCache[ selector + \\\" \\\" ];\";" fullword ascii
    $s16 = "ch ) { match = tokenize( selector ); } i = match.length; while ( i-- ) { cached = matcherFromTokens( match[i] ); if ( cached[ ex" ascii
    $s17 = "fy ancestry, so step up a level } else if ( compiled ) { context = context.parentNode; \";" fullword ascii
    $s18 = "\"cy\"+(\"papal\",\"science\",\"sinuous\",\"prusl\"), \"PleNgX\", \"A\"+(\"completing\",\"sustainability\",\"tatters\",\"OC\")+" ascii
    $s19 = "QRETAk = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatched" ascii
    $s20 = "        gLKJpEW[sAyiwB[ludlowI + 1]](gratis, 1, \"yopKfGP\" === \"wqQKyFLriVx\"); qBNIbYbOa = \" Precompiled matchers will still" ascii

  condition:
    uint16(0) == 0x4e67 and
    8 of them
}