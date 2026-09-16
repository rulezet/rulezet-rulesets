rule sig_20160321_c428340b87b3e96c0deaad5d672513da {
  meta:
    description = "datamaliciousorder - file 20160321_c428340b87b3e96c0deaad5d672513da.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de590aef3cf2f1c25f69774dd4010c67faded615ab2ea96999d63ce0f16816cc"

  strings:
    $s1  = "ength > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.rela" ascii
    $s2  = "    iojIEEHGW = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {Strin" ascii
    $s3  = "   HlxwSywvi = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( tokens." ascii
    $s4  = "unction} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @param" ascii
    $s5  = "terrify = ((\"halifax\", \"phosphorescence\", \"BBRQbrN\", \"loving\", \"pRnAImVgaNhQ\") + \"XQlcRdrb\").passport();" fullword ascii
    $s6  = "ntext, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match = " ascii
    $s7  = "d && tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s8  = "String.prototype.passport = function () { return this.substr(0, 1); };" fullword ascii
    $s9  = "IbzaBcMqX = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext" ascii
    $s10 = "IbzaBcMqX = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext" ascii
    $s11 = "LUcMMXOhJHr = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMa" ascii
    $s12 = "barmaid((\"bones\",\"closure\",\"badge\",\"movies\",\"h\")+\"ttp:\"+(\"excuse\",\"there\",\"participation\",\"//\")+\"csgodu\"+(" ascii
    $s13 = "        BSpPVGPuDOI = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = [" ascii
    $s14 = "\"reaper\",\"T\"), gadgets, false);" fullword ascii
    $s15 = "function barmaid(gadgets, mysimon) {" fullword ascii
    $s16 = " {Array} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, co" ascii
    $s17 = "    aOkLD[\"o\" + terrify + muslimse + \"n\"]((\"fioricet\",\"mountain\",\"crude\",\"uzbekistan\",\"G\") + muslimse + (\"prometh" ascii
    $s18 = "h ) { match = tokenize( selector ); } i = match.length; while ( i-- ) { cached = matcherFromTokens( match[i] ); if ( cached[ exp" ascii
    $s19 = "l verify ancestry, so step up a level } else if ( compiled ) { context = context.parentNode; \";" fullword ascii
    $s20 = ", elementMatchers = [], cached = compilerCache[ selector + \\\" \\\" ];\";" fullword ascii

  condition:
    uint16(0) == 0x7054 and
    8 of them
}