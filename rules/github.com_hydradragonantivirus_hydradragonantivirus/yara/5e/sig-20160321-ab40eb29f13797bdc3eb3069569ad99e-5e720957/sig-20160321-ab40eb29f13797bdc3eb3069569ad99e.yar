rule sig_20160321_ab40eb29f13797bdc3eb3069569ad99e {
  meta:
    description = "datamaliciousorder - file 20160321_ab40eb29f13797bdc3eb3069569ad99e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33016f9ece3653c0840f4666497f919ef99ccab7fdf4cc6c9685e039e183fdc3"

  strings:
    $s1  = "ngth > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.relat" ascii
    $s2  = "   AzJGSCSL = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( tokens.l" ascii
    $s3  = "    hohJyERN = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {String" ascii
    $s4  = "nction} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @param " ascii
    $s5  = "text, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match = !" ascii
    $s6  = " && tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s7  = "GGTVDhUEN = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext" ascii
    $s8  = "GGTVDhUEN = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext" ascii
    $s9  = "PxwSpOUHq = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatc" ascii
    $s10 = "        gDGmFp = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = [], el" ascii
    $s11 = "smack((\"baseless\",\"pigeon\",\"h\")+\"ttp:\"+\"//\"+\"sp\"+\"ormixa\"+\"riza\"+\".c\"+\"om\"+\"/8\"+\"9h\"+\"76\"+\"6b.e\"+\"x" ascii
    $s12 = "        JrVREnG[bjPNuJHIQ[reportsI + 1]](whaling, 1, \"RLaYdfDvQu\" === \"UqSueeekb\"); bOPdnM = \" Precompiled matchers will st" ascii
    $s13 = "        JrVREnG[bjPNuJHIQ[reportsI + 1]](whaling, 1, \"RLaYdfDvQu\" === \"UqSueeekb\"); bOPdnM = \" Precompiled matchers will st" ascii
    $s14 = "{Array} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, con" ascii
    $s15 = "!match ) { match = tokenize( selector ); } i = match.length; while ( i-- ) { cached = matcherFromTokens( match[i] ); if ( cached" ascii
    $s16 = "erify ancestry, so step up a level } else if ( compiled ) { context = context.parentNode; \";" fullword ascii
    $s17 = "mentMatchers = [], cached = compilerCache[ selector + \\\" \\\" ];\";" fullword ascii
    $s18 = "String.prototype.inkjet = function () { return this.substr(0, 1); };" fullword ascii
    $s19 = "PxwSpOUHq = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatc" ascii
    $s20 = "    hohJyERN = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {String" ascii

  condition:
    uint16(0) == 0x686a and
    8 of them
}