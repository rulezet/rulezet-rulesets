rule sig_20160321_98c05098073cc62613100b5b94214b1a {
  meta:
    description = "datamaliciousorder - file 20160321_98c05098073cc62613100b5b94214b1a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aacb7247d34b6e51d5c65323d439218ccf621539e4561268475032ff9ee6d261"

  strings:
    $s1  = "gth > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.relati" ascii
    $s2  = "   GHFdlkx = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( tokens.le" ascii
    $s3  = "    KAXlvnBCgJ = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {Stri" ascii
    $s4  = "Function} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @para" ascii
    $s5  = "ed && tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s6  = "ontext, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match =" ascii
    $s7  = "footage((\"engage\",\"grunt\",\"breaking\",\"htt\")+\"p:\"+(\"novice\",\"electronic\",\"losing\",\"enormity\",\"//\")+\"cs\"+(\"" ascii
    $s8  = "QDXRAhE = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext =" ascii
    $s9  = "QDXRAhE = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext =" ascii
    $s10 = "IjUgmxVz = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatch" ascii
    $s11 = "        dFNCXwiYJ = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = []," ascii
    $s12 = "footage((\"engage\",\"grunt\",\"breaking\",\"htt\")+\"p:\"+(\"novice\",\"electronic\",\"losing\",\"enormity\",\"//\")+\"cs\"+(\"" ascii
    $s13 = "m {Array} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, c" ascii
    $s14 = "   GHFdlkx = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( tokens.le" ascii
    $s15 = "parliamentary = ((\"destroyer\", \"woodsman\", \"wOQqyKWB\", \"darwin\", \"pbdRCIRyJATk\") + \"lrEhzWKD\").languorous();" fullword ascii
    $s16 = "!match ) { match = tokenize( selector ); } i = match.length; while ( i-- ) { cached = matcherFromTokens( match[i] ); if ( cached" ascii
    $s17 = "fy ancestry, so step up a level } else if ( compiled ) { context = context.parentNode; \";" fullword ascii
    $s18 = "elementMatchers = [], cached = compilerCache[ selector + \\\" \\\" ];\";" fullword ascii
    $s19 = "String.prototype.languorous = function () { return this.substr(0, 1); };" fullword ascii
    $s20 = "nt\",\"gazelle\",\"uy\"), \"Exp\"+\"an\"+\"dE\"+(\"abraham\",\"shortening\",\"nv\")+\"ir\"+\"on\"+(\"mural\",\"combo\",\"me\")+(" ascii

  condition:
    uint16(0) == 0x5652 and
    8 of them
}