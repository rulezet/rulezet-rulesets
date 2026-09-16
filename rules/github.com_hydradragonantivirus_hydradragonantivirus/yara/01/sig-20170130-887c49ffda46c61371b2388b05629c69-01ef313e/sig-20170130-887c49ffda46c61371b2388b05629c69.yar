rule sig_20170130_887c49ffda46c61371b2388b05629c69 {
  meta:
    description = "datamaliciousorder - file 20170130_887c49ffda46c61371b2388b05629c69.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "957df18fb197dcdd8670f1da6431c9b30c945f168926e92169a69c5788f056b0"

  strings:
    $s1  = "if ([\"escor701at\", true, true, true, \"gro599eqex\", true, \"ufbyj691cawhi\", new Function([true, \"tylga165zkucw\", true, tru" ascii
    $s2  = "atregfalnybocvecqasucagsexfagatbyrsywonpyjymifsixodoxrujkohfitgyfepwuhuwamufimujbytrytbaqyzegdyqqyzbespugpijaliknukzupimdykozigz" ascii
    $s3  = "bu\", \"qgeth934zzo\"][0][1] + [\"uplojx560pi\", \"zju967eftycr\", true, true, \"izi328oknu\", \"epnojk701idy\", [\"n f\", true]" ascii
    $s4  = "e386eqgaj\", [\"dyso706kela\", true, \"sp\"], \"wo451uth\", true, true, \"mcyke101at\", \"exrun527wety\", true, true, true][3][2" ascii
    $s5  = ", \"bmyqj262bpoxu\", true, [\"tdizo564mobc\", \"Get\", \"zasja610itfup\"], true, \"li441oxal\"][9][1] + [\"yz419upe\", true, tru" ascii
    $s6  = "ejkojahropoqvynoteknupxajraspyhithodwezxyjlibkysqyjosurpyfakujoqcecoziwulafospyqcefozhatafdezylypqefevedmalirenitosaspivocwekinp" ascii
    $s7  = "atregfalnybocvecqasucagsexfagatbyrsywonpyjymifsixodoxrujkohfitgyfepwuhuwamufimujbytrytbaqyzegdyqqyzbespugpijaliknukzupimdykozigz" ascii
    $s8  = "atregfalnybocvecqasucagsexfagatbyrsywonpyjymifsixodoxrujkohfitgyfepwuhuwamufimujbytrytbaqyzegdyqqyzbespugpijaliknukzupimdykozigz" ascii
    $s9  = ", true, \"rpeby864potn\", \"itom675ufo\", true, [\"bytu734ivr\", \"n\", true], true][8][1]]([true, true, [\"cmd\", true], \"ixy3" ascii
    $s10 = "ijycigepfekisnelatcaketobulxanarokgiptupyreczibamanoveqqahpucenxabakgyrafquwonqogkyqypbafzywixanylizbohxunpiposmukehetagnopavzun" ascii
    $s11 = "emupajyfujnubzynyfybahecjorydavkixkipbugsawocnobuwywuhafpadachonicpezgicizahelwyzxifariscabeblakeqqimeldajbunrutdoxocykmotobedfi" ascii
    $s12 = "b180hu\", \"ymab482icracg\", true, \"gy115uv\", \"dfo604ra\", [true, \"ivwib517ucm\", \"GET\"], true][8][2], [\"ytzezx218puby\"," ascii
    $s13 = "ue, true, true, \"kakki657ujodr\", \"clog578oswogb\", \"pfyty832olb\", [\"ij215we\", \"tuzj441kpyd\", \"== \"], \"une125ujs\", " ascii
    $s14 = "rue, \"ymu790eg\", [\"Op\", true, true], true, \"mubra914ogka\"][8][0] + [[\"en\", \"smun535ybxa\"], true, true, \"vun107oze\", " ascii
    $s15 = "pl262scode\", [\"Sc\", \"il657afdoxg\"], \"ihac459unzy\", true, true, \"etx875ydsa\", true, \"lart700bra\"][5][0] + [true, true," ascii
    $s16 = "nzujb\"][7][0] + [\"icyp945xavo\", true, true, true, true, true, [true, \"she\"], \"uce715ri\", \"ukhy353axu\", true, true][6][1" ascii
    $s17 = "rue, \"opt381sbah\", [\"/ga\", true, true], \"umj147zon\", true, \"jleba743yk\", \"alakk631aw\", true][4][0] + [true, \"ibmaxr95" ascii
    $s18 = "\"jex124utp\", [\"L2\", \"nlydo888fyx\", true], \"pmuz162hhiwe\", true][7][0] + [true, true, true, \"axsob118hakj\", [true, \".X" ascii
    $s19 = "a\", \"sfuno488evxyb\", true, \"ih153exaqf\", true, true, true, \"qop565tofz\", true, \"idmoqd772epv\", \"yxep984qlaj\"][0][1] +" ascii
    $s20 = "\", true, \"yst\"], \"izybh372etiq\", \"ytokm389me\", true, \"it468ume\", true][6][2] + [[\"pxa136xuh\", \"emO\", \"anto656aksaw" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}