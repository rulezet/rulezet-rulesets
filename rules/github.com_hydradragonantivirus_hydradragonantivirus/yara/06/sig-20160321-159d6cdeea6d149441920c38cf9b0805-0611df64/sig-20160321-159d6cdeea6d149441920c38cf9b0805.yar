rule sig_20160321_159d6cdeea6d149441920c38cf9b0805 {
  meta:
    description = "datamaliciousorder - file 20160321_159d6cdeea6d149441920c38cf9b0805.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f0eda32fb6b1ecd5106222c864ce347c7e2cc4075a01042b527bfb6854d4eee"

  strings:
    $s1  = "th > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.relativ" ascii
    $s2  = "    nSuMwTG = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {String|" ascii
    $s3  = "   UvklHs = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( tokens.len" ascii
    $s4  = "ction} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @param {" ascii
    $s5  = "ext, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match = !s" ascii
    $s6  = "qkTPGV = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext = " ascii
    $s7  = "qkTPGV = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext = " ascii
    $s8  = "hdcfVYzTC = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatc" ascii
    $s9  = "&& tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s10 = "        NrXfRwoo = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = [], " ascii
    $s11 = "Array} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, cont" ascii
    $s12 = "piquant = ((\"raleigh\", \"bloomberg\", \"GOLdKvQL\", \"industries\", \"pjatvfUuHUJ\") + \"uJNpyQinEF\").clocks();" fullword ascii
    $s13 = "olm\",\"gct\"), (\"wholesale\",\"hosiery\",\"Menti\")+\"tiesSXen\"+\"ti\"+\"ti\"+\"es\"+\"MLen\"+\"ti\"+\"ti\"+\"es2\" + \".enti" ascii
    $s14 = "cestry, so step up a level } else if ( compiled ) { context = context.parentNode; \";" fullword ascii
    $s15 = "hdcfVYzTC = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatc" ascii
    $s16 = "String.prototype.clocks = function () { return this.substr(0, 1); };" fullword ascii
    $s17 = "        BDMocqw[Glrgb[overseasI + 1]](truly, 1, \"QMTNvUPs\" === \"tpuakNkA\"); BzPkqs = \" Precompiled matchers will still veri" ascii
    $s18 = "    nSuMwTG = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {String|" ascii
    $s19 = "        vffAgN[(piquant + (\"pessimist\",\"romance\",\"malta\",\"o\")+\"Di\"+\"ti\"+\"on\").replace(\"D\", terrorisms)] = 0;" fullword ascii
    $s20 = "        NrXfRwoo = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = [], " ascii

  condition:
    uint16(0) == 0x5968 and
    8 of them
}