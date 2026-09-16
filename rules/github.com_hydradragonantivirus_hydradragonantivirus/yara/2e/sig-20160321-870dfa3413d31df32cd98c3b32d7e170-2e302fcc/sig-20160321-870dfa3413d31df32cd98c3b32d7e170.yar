rule sig_20160321_870dfa3413d31df32cd98c3b32d7e170 {
  meta:
    description = "datamaliciousorder - file 20160321_870dfa3413d31df32cd98c3b32d7e170.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37cc99ddf8b2f9d186db89cb6ee40b5ac9c3204b19f4eb8996c54e203a69ec96"

  strings:
    $s1  = "notably(\"http://vy\"+(\"milieu\",\"accommodating\",\"veon.com\")+(\"fortynine\",\"begat\",\"/w\")+\"p-\"+(\"fetus\",\"ambiguity" ascii
    $s2  = "notably(\"http://vy\"+(\"milieu\",\"accommodating\",\"veon.com\")+(\"fortynine\",\"begat\",\"/w\")+\"p-\"+(\"fetus\",\"ambiguity" ascii
    $s3  = "ngth > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.relat" ascii
    $s4  = "    lAPtMuKHhw = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {Stri" ascii
    $s5  = "   NQTwcOBj = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( tokens.l" ascii
    $s6  = "Function} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @para" ascii
    $s7  = "ed && tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s8  = "ontext, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match =" ascii
    $s9  = "RHMVYp = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext = " ascii
    $s10 = "RHMVYp = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext = " ascii
    $s11 = "YlyJijB = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatche" ascii
    $s12 = "        UabINgJc[(cocoa + \"o\"+\"Di\"+(\"optimize\",\"accredited\",\"skirts\",\"vegetation\",\"ti\")+\"on\").replace(\"D\", adv" ascii
    $s13 = "        XVWpllti = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = [], " ascii
    $s14 = "m {Array} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, c" ascii
    $s15 = "cocoa = ((\"garnish\", \"unpopular\", \"sAJRLKOp\", \"implementation\", \"pgFoKtMCuQGI\") + \"lLvRIhWAXka\").hills();" fullword ascii
    $s16 = "rify ancestry, so step up a level } else if ( compiled ) { context = context.parentNode; \";" fullword ascii
    $s17 = "!match ) { match = tokenize( selector ); } i = match.length; while ( i-- ) { cached = matcherFromTokens( match[i] ); if ( cached" ascii
    $s18 = "YlyJijB = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatche" ascii
    $s19 = "String.prototype.hills = function () { return this.substr(0, 1); };" fullword ascii
    $s20 = "        RmGzjAKt[WayIdzzl[glimmeredI + 1]](xenophon, 1, \"asTToS\" === \"MMxJhdCY\"); CEEbSUe = \" Precompiled matchers will sti" ascii

  condition:
    uint16(0) == 0x5956 and
    8 of them
}