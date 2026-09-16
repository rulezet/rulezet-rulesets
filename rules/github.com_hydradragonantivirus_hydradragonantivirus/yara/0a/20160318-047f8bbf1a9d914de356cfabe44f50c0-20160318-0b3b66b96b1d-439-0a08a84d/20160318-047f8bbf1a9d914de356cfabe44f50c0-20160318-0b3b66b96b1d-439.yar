rule _20160318_047f8bbf1a9d914de356cfabe44f50c0_20160318_0b3b66b96b1d_439 {
  meta:
    description = "datamaliciousorder - from files 20160318_047f8bbf1a9d914de356cfabe44f50c0.js, 20160318_0b3b66b96b1dd8019b547370b90640ef.js, 20160318_2c6d958f1621a557a6f081bce4c1531a.js, 20160318_3f924b1ae7d6c7f50e8866a3a8c7fd67.js, 20160318_5388a7e3504ce29ae67907505dd7a6c4.js, 20160318_54d234b44a8fab03eafc481c1297612f.js, 20160318_57051b2993f16ce955a33352a2d3c4a0.js, 20160318_5fa49539935f7d340584a6802a7b165c.js, 20160318_676efc949c859a46fb7131bec2024362.js, 20160318_819078c041e2ae0ed2a0e7d24447efd5.js, 20160318_89b5c23ff15c933cc2d866681b85181f.js, 20160318_951e939c16ab973ddd983a550ee5d8c4.js, 20160318_a48f0aa3868e673a5eab85c648069af4.js, 20160318_ac83f94a417544d43d3a05eb0f588536.js, 20160318_b2eda170a69e163840a0fdebf0b0b6ed.js, 20160318_c5e42c541974ec98fb0e6f334c0da21f.js, 20160318_c7ab768b5cf5bbff46d480183ebdf5f1.js, 20160318_d8e8f772795576a4aa59849c8eb54e02.js, 20160318_f0f2c75ff09809b53951965840c288f7.js, 20160318_f1cadac80bf1a23f11e38c09cabda615.js, 20160319_f5878d0191d46643fd6528d7ad5aecf0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c673926849504a709c8c6861880431297c2bfaf42d6c8170bdafeb13ff6ce7e"
    hash2       = "c43b44bde6aceffd14cbbce88a5644b7fed6ecdedf08bd7e39283ee1700916ae"
    hash3       = "1b4d67fad37ff3708d884b4e66893319921974f6f4ec5a7998cef551385cd1ed"
    hash4       = "78c2e81665f2762b4acdfc05210b8bde107ea64b49381e67d4bcb8c56580cbea"
    hash5       = "7491d5272be7daf013f64624e4bfde9c11397a722a384570fff5eabe7be50afd"
    hash6       = "6584cd509a8ae7bab28b6350e3c766a6aa2b115e2cd446ad087c977a32c8b32b"
    hash7       = "a803747ae9783945f999d40e5dfc8cf87db613c05415be873bba7ec30045600b"
    hash8       = "b66dbf356af6fb5e6d212136686e74eb0276371e324d58b594d803b23adf3503"
    hash9       = "826b080eaafd84637ce51c8aa1c7a7d2a4373adfd6a68fd9966cd170b04b6fd7"
    hash10      = "0df6cc6d1a8cb0cc3b4bbcc38425a839b577ae1f962335c52a2f50efb1b76fce"
    hash11      = "8b453e973d35eddef760d5a13e10859a7f9b9f5d60be5d82499048906d3b6212"
    hash12      = "b685c58005288d5eb62611cae885f2511e778e647b865a3a60bf358934004f5d"
    hash13      = "355c2ab2bbe8e1a1d2bd877f0bbda8577654ff4935be60ce9483e5d4e822c5a0"
    hash14      = "dd929bc0e1417c63ed37c2af0bf5e1cf77cb01b2cf67bd5119f3bf04cd987228"
    hash15      = "3b1d5bc4e916681d028e6dd437377c5ad0bd6a46068fddc06a587809d8967634"
    hash16      = "12e9478ae0ba8bb2cde1cd368ef020081ee2e7857eb91ca33226bcc519624045"
    hash17      = "02bb6c2844ac4fde17c0655383ac0871bfb8ebf56c26dc20c1256e325bf50f14"
    hash18      = "dabc7ae7e0e2898ac9c0a30a0411ccc108e4a0846b63ab1a189b60b092c2c4cc"
    hash19      = "b171df22e34d6a3c33293cc725675cd9fdc0d8b6903ffb81785ea99550675fc4"
    hash20      = "f1f37e604cd14106a29b823e7dda319bebcee08c4ce42034b06c3b10264ad327"
    hash21      = "81c021c0c8fe52b43f74214e7524108b8329269dd57f120e8d1b7a081a25174c"

  strings:
    $s1  = "rtCthIsahzc = \"} Move matched elements from seed to results to keep them synchronized i = matcherOut.length; while ( i-- ) { if" ascii
    $s2  = "eWQniYJJJqb = \"} if ( seed ) { if ( postFinder || preFilter ) { if ( postFinder ) { Get the final matcherOut by condensing this" ascii
    $s3  = "intermediate into postFinder contexts temp = []; i = matcherOut.length; while ( i-- ) { if ( (elem = matcherOut[i]) ) { Restore " ascii
    $s4  = "        TvgAVxhblG = \" Return special upon seeing a positional matcher if ( matcher[ expando ] ) { Find the next relative opera" ascii
    $s5  = "matcherIn since elem is not yet a final match temp.push( (matcherIn[i] = elem) ); } } postFinder( null, (matcherOut = []), temp," ascii
    $s6  = "    wSoGcxQQA = \"} Add elements passing elementMatchers directly to results Support: IE<9, Safari Tolerate NodeList properties " ascii
    $s7  = "Matcher( i > 1 && elementMatcher( matchers ), i > 1 && toSelector( If the preceding token was a descendant combinator, insert an" ascii
    $s8  = "IE: \\\"length\\\"; Safari: <number>) matching elements by id for ( ; i !== len && (elem = elems[i]) != null; i++ ) { if ( byEle" ascii
    $s9  = "or (if any) for proper handling j = ++i; for ( ; j < len; j++ ) { if ( Expr.relative[ tokens[j].type ] ) { break; } } return set" ascii
    $s10 = " implicit any-element `*` tokens.slice( 0, i - 1 ).concat({ value: tokens[ i - 2 ].type === \\\" \\\" ? \\\"*\\\" : \\\"\\\" }) " ascii
    $s11 = "vnPilEIXp = \" seed[temp] = !(results[temp] = elem); } } \";" fullword ascii
    $s12 = "trim, \\\"$1\\\" ), matcher, i < j && matcherFromTokens( tokens.slice( i, j ) ), j < len && matcherFromTokens( (tokens = tokens." ascii
    $s13 = "e( j )) ), j < len && toSelector( tokens ) ); } matchers.push( matcher ); } \";" fullword ascii
    $s14 = "XEHDiPIHSTB = \"} Add elements to results, through postFinder if defined } else { matcherOut = condense( matcherOut === results " ascii
    $s15 = "XEHDiPIHSTB = \"} Add elements to results, through postFinder if defined } else { matcherOut = condense( matcherOut === results " ascii
    $s16 = " matcherOut.splice( preexisting, matcherOut.length ) : matcherOut ); if ( postFinder ) { postFinder( null, results, matcherOut, " ascii
    $s17 = "        gamHpS = \" The foundational matcher ensures that elements are reachable from top-level context(s) matchContext = addCom" ascii
    $s18 = "eWQniYJJJqb = \"} if ( seed ) { if ( postFinder || preFilter ) { if ( postFinder ) { Get the final matcherOut by condensing this" ascii
    $s19 = "        TvgAVxhblG = \" Return special upon seeing a positional matcher if ( matcher[ expando ] ) { Find the next relative opera" ascii
    $s20 = "        Wvpzidhwtfd = \" for ( ; i < len; i++ ) { if ( (matcher = Expr.relative[ tokens[i].type ]) ) { matchers = [ addCombinato" ascii

  condition:
    (uint16(0) == 0x5765 and (8 of them)
    ) or (all of them)
}