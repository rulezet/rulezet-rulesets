rule sig_20160321_994527b006527645f7da1d21afd78bcd {
  meta:
    description = "datamaliciousorder - file 20160321_994527b006527645f7da1d21afd78bcd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3500873559148454a1fe02619dbaf37df87d392a1e017842da5a364516d5bce6"

  strings:
    $s1  = "length > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.rel" ascii
    $s2  = "    tjbAsaFjmSd = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {Str" ascii
    $s3  = "   OUqymbkJPN = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( tokens" ascii
    $s4  = "|Function} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @par" ascii
    $s5  = "context, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match " ascii
    $s6  = "eed && tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s7  = "cSJXgJrVP = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext" ascii
    $s8  = "cSJXgJrVP = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext" ascii
    $s9  = "NjSuhEO = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatche" ascii
    $s10 = "        OljKwbyW = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = [], " ascii
    $s11 = "am {Array} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, " ascii
    $s12 = "rudimentary = ((\"counties\", \"backup\", \"AwNcqCQBK\", \"clarke\", \"pPKDiBlIeR\") + \"OKJmtDe\").thats();" fullword ascii
    $s13 = "fy ancestry, so step up a level } else if ( compiled ) { context = context.parentNode; \";" fullword ascii
    $s14 = "String.prototype.thats = function () { return this.substr(0, 1); };" fullword ascii
    $s15 = "NjSuhEO = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatche" ascii
    $s16 = "    tjbAsaFjmSd = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {Str" ascii
    $s17 = "        fVlGUBW[(rudimentary + \"o\"+(\"computing\",\"selfishly\",\"Di\")+(\"giving\",\"agate\",\"among\",\"ti\")+\"on\").replac" ascii
    $s18 = "        fVlGUBW[(rudimentary + \"o\"+(\"computing\",\"selfishly\",\"Di\")+(\"giving\",\"agate\",\"among\",\"ti\")+\"on\").replac" ascii
    $s19 = "        OljKwbyW = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = [], " ascii
    $s20 = "   OUqymbkJPN = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( tokens" ascii

  condition:
    uint16(0) == 0x4843 and
    8 of them
}