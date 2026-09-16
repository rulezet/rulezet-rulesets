rule sig_20160321_91388e82167820ff7b82aa4b4f7f2afc {
  meta:
    description = "datamaliciousorder - file 20160321_91388e82167820ff7b82aa4b4f7f2afc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2cdb265bb75390f46666073afd315772f35b3a7a35d837d71e3cf1f6693c17e"

  strings:
    $s1  = "ngth > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.relat" ascii
    $s2  = "    zMXOBGq = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {String|" ascii
    $s3  = "   fpqdDMCp = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( tokens.l" ascii
    $s4  = "ction} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @param {" ascii
    $s5  = "ext, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match = !s" ascii
    $s6  = "YaQroplzPVw = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostConte" ascii
    $s7  = "YaQroplzPVw = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostConte" ascii
    $s8  = "\",\"throwing\",\"worth\",\"%\")+(\"widower\",\"abeyance\",\"drops\",\"wells\",\"TE\")+\"MP%\", (\"overbearing\",\"vegetarian\"," ascii
    $s9  = "DPAtcfux = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatch" ascii
    $s10 = "&& tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s11 = "        sJFNfY = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = [], el" ascii
    $s12 = "Array} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, cont" ascii
    $s13 = " verify ancestry, so step up a level } else if ( compiled ) { context = context.parentNode; \";" fullword ascii
    $s14 = "tch ) { match = tokenize( selector ); } i = match.length; while ( i-- ) { cached = matcherFromTokens( match[i] ); if ( cached[ e" ascii
    $s15 = "DPAtcfux = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatch" ascii
    $s16 = "String.prototype.second = function () { return this.substr(0, 1); };" fullword ascii
    $s17 = "mentMatchers = [], cached = compilerCache[ selector + \\\" \\\" ];\";" fullword ascii
    $s18 = "        sJFNfY = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = [], el" ascii
    $s19 = "        JTyhfSJB[eCSwPWHb[transmutationI + 1]](arrival, 1, \"Nyuzpo\" === \"yshIrrWBmL\"); QkMnt = \" Precompiled matchers will " ascii
    $s20 = "    zMXOBGq = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {String|" ascii

  condition:
    uint16(0) == 0x7676 and
    8 of them
}