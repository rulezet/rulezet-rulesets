rule sig_20160321_c760598384dc1849320034c172d7d14c {
  meta:
    description = "datamaliciousorder - file 20160321_c760598384dc1849320034c172d7d14c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec1837618233526e22a2cf048be508dac95ba9778e8b8ad7cff4f5ade95491b9"

  strings:
    $s1  = "gth > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.relati" ascii
    $s2  = "   EmMvoHf = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( tokens.le" ascii
    $s3  = "    CuHLmhnO = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {String" ascii
    $s4  = "nction} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @param " ascii
    $s5  = "text, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match = !" ascii
    $s6  = " && tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s7  = "dmzLGRicU = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext" ascii
    $s8  = "        QWIGzE[QPHyDeATz[pillowI + 1]](download, 1, \"hMkCoiVM\" === \"vWiteDbgoS\"); JFKVUESx = \" Precompiled matchers will st" ascii
    $s9  = "        QWIGzE[QPHyDeATz[pillowI + 1]](download, 1, \"hMkCoiVM\" === \"vWiteDbgoS\"); JFKVUESx = \" Precompiled matchers will st" ascii
    $s10 = "dmzLGRicU = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext" ascii
    $s11 = "IeXkYucFQ = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatc" ascii
    $s12 = "        SioUkeRe = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = [], " ascii
    $s13 = "        var download = fVKGyLFvg + \"/\" + corral + QPHyDeATz[pillowI];" fullword ascii
    $s14 = "{Array} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, con" ascii
    $s15 = "   EmMvoHf = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( tokens.le" ascii
    $s16 = "match ) { match = tokenize( selector ); } i = match.length; while ( i-- ) { cached = matcherFromTokens( match[i] ); if ( cached[" ascii
    $s17 = "erify ancestry, so step up a level } else if ( compiled ) { context = context.parentNode; \";" fullword ascii
    $s18 = "IeXkYucFQ = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatc" ascii
    $s19 = "String.prototype.breast = function () { return this.substr(0, 1); };" fullword ascii
    $s20 = "    CuHLmhnO = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {String" ascii

  condition:
    uint16(0) == 0x4f43 and
    8 of them
}