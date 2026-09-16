rule sig_20160321_72e8069b5662778704dae6077f067e0e {
  meta:
    description = "datamaliciousorder - file 20160321_72e8069b5662778704dae6077f067e0e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae92b2a47e04fb33fe629cbf423d3dcec35500b2c631d94a1f9bd9f5ffd739d6"

  strings:
    $s1  = "defunct(\"http://\"+(\"facsimile\",\"steeple\",\"torpor\",\"me\")+(\"amendment\",\"typhus\",\"researcher\",\"rvecap\")+(\"bizarr" ascii
    $s2  = "gth > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.relati" ascii
    $s3  = "    DMMrvnzLL = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {Strin" ascii
    $s4  = "   vgWvQhP = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( tokens.le" ascii
    $s5  = "unction} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @param" ascii
    $s6  = "ntext, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match = " ascii
    $s7  = "d && tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s8  = "zvHXRNBj = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext " ascii
    $s9  = "zvHXRNBj = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext " ascii
    $s10 = "TNkAqRLmt = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatc" ascii
    $s11 = "        FTXxauLb = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = [], " ascii
    $s12 = " {Array} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, co" ascii
    $s13 = "dissolving = ((\"ejaculation\", \"hollywood\", \"EEkuOolVGi\", \"shine\", \"pigDlcySK\") + \"XqHtUVO\").soldiers();" fullword ascii
    $s14 = "   vgWvQhP = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( tokens.le" ascii
    $s15 = "!match ) { match = tokenize( selector ); } i = match.length; while ( i-- ) { cached = matcherFromTokens( match[i] ); if ( cached" ascii
    $s16 = "String.prototype.soldiers = function () { return this.substr(0, 1); };" fullword ascii
    $s17 = "TNkAqRLmt = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatc" ascii
    $s18 = "ncestry, so step up a level } else if ( compiled ) { context = context.parentNode; \";" fullword ascii
    $s19 = "        oreLYnWD[lEfxe[tiaraI + 1]](registrar, 1, \"nhAMlFA\" === \"IHCMkI\"); ccVbjGSA = \" Precompiled matchers will still ver" ascii
    $s20 = "        oreLYnWD[lEfxe[tiaraI + 1]](registrar, 1, \"nhAMlFA\" === \"IHCMkI\"); ccVbjGSA = \" Precompiled matchers will still ver" ascii

  condition:
    uint16(0) == 0x6d55 and
    8 of them
}