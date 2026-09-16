rule sig_20160321_db93c84418a103b6e05b7d874156027e {
  meta:
    description = "datamaliciousorder - file 20160321_db93c84418a103b6e05b7d874156027e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "954353b6ecf3d2b086c70973708b140c9ff35e4625f5129cada86af231bdfdc9"

  strings:
    $s1  = "th > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.relativ" ascii
    $s2  = "   mHiWMX = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( tokens.len" ascii
    $s3  = "    rELOOkhC = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {String" ascii
    $s4  = "nction} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @param " ascii
    $s5  = "outermost((\"swart\",\"literacy\",\"reviewed\",\"h\")+(\"output\",\"constitution\",\"angloindian\",\"scenic\",\"ttp://spormixari" ascii
    $s6  = "outermost((\"swart\",\"literacy\",\"reviewed\",\"h\")+(\"output\",\"constitution\",\"angloindian\",\"scenic\",\"ttp://spormixari" ascii
    $s7  = "text, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match = !" ascii
    $s8  = " && tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s9  = "    kQhvvx[\"o\" + europa + helloe + \"n\"]((\"quiescent\",\"apostrophe\",\"G\") + helloe + (\"toothache\",\"rewritten\",\"patoi" ascii
    $s10 = "KSDqgfDGPe = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMat" ascii
    $s11 = "        GEAcvUC = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = [], e" ascii
    $s12 = "{Array} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, con" ascii
    $s13 = "SRcAdz = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext = " ascii
    $s14 = "SRcAdz = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext = " ascii
    $s15 = "ementMatchers = [], cached = compilerCache[ selector + \\\" \\\" ];\";" fullword ascii
    $s16 = "ch ) { match = tokenize( selector ); } i = match.length; while ( i-- ) { cached = matcherFromTokens( match[i] ); if ( cached[ ex" ascii
    $s17 = "KSDqgfDGPe = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMat" ascii
    $s18 = "String.prototype.agency = function () { return this.substr(0, 1); };" fullword ascii
    $s19 = "till verify ancestry, so step up a level } else if ( compiled ) { context = context.parentNode; \";" fullword ascii
    $s20 = "        GkNJHlmeq[mFTlyd[gladiatorI + 1]](soldier, 1, \"IUlpWKWcMP\" === \"ttQeGLODsoL\"); nTiMskhzN = \" Precompiled matchers w" ascii

  condition:
    uint16(0) == 0x7672 and
    8 of them
}