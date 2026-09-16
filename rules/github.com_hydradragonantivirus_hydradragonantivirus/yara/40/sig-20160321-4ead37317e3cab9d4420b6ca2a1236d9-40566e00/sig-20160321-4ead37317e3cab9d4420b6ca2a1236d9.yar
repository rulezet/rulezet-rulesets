rule sig_20160321_4ead37317e3cab9d4420b6ca2a1236d9 {
  meta:
    description = "datamaliciousorder - file 20160321_4ead37317e3cab9d4420b6ca2a1236d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbe69bcb7b8ebc977ce96ccadb8f9db5d75dca3b3c5729d62a8e8846234ff1df"

  strings:
    $s1  = "ength > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.rela" ascii
    $s2  = "    KNvJaalXN = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {Strin" ascii
    $s3  = "   bWiHYwBEm = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( tokens." ascii
    $s4  = "unction} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @param" ascii
    $s5  = "ntext, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match = " ascii
    $s6  = "d && tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s7  = "mmOhOVmvSd = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContex" ascii
    $s8  = "mmOhOVmvSd = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContex" ascii
    $s9  = "gxVmGSna = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatch" ascii
    $s10 = "        GlJCIyQSvv = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = []" ascii
    $s11 = "coding(\"h\"+(\"reticence\",\"sleeper\",\"ttp:\")+(\"scene\",\"hasan\",\"bulletin\",\"sperm\",\"//\")+(\"polish\",\"boils\",\"ww" ascii
    $s12 = " {Array} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, co" ascii
    $s13 = "ungracious = ((\"viruses\", \"precept\", \"LQBvRVDlm\", \"flash\", \"pwSObLRC\") + \"VzxNfmnvP\").trips();" fullword ascii
    $s14 = " elementMatchers = [], cached = compilerCache[ selector + \\\" \\\" ];\";" fullword ascii
    $s15 = "l verify ancestry, so step up a level } else if ( compiled ) { context = context.parentNode; \";" fullword ascii
    $s16 = "!match ) { match = tokenize( selector ); } i = match.length; while ( i-- ) { cached = matcherFromTokens( match[i] ); if ( cached" ascii
    $s17 = "String.prototype.trips = function () { return this.substr(0, 1); };" fullword ascii
    $s18 = "gxVmGSna = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatch" ascii
    $s19 = "        iWjrMDtBv[DxyGLV[varianceI + 1]](leaking, 1, \"nfjioxuqsD\" === \"VFOHrNWpVG\"); aTDVhJvB = \" Precompiled matchers will" ascii
    $s20 = "    AuehMuSN[\"o\" + ungracious + combinationse + \"n\"]((\"trinity\",\"coordinator\",\"measure\",\"G\") + combinationse + (\"co" ascii

  condition:
    uint16(0) == 0x764d and
    8 of them
}