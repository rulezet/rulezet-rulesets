rule sig_20170130_5e933ab92742aef1e221c36aa3e7dd4e {
  meta:
    description = "datamaliciousorder - file 20170130_5e933ab92742aef1e221c36aa3e7dd4e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "102795e81571188857cda9f2a9a5147f4f3628afbc882578335b6a0b486ac7fa"

  strings:
    $s1  = "lbexanoqxuhulkefygredfofvuwulpejubmaqepwubugekcoxjaxigfeqihqemzasmukfarxehfeklecqehitijacbebazlupyzipivygapiresnurrukykconfezdyg" ascii
    $s2  = "lbexanoqxuhulkefygredfofvuwulpejubmaqepwubugekcoxjaxigfeqihqemzasmukfarxehfeklecqehitijacbebazlupyzipivygapiresnurrukykconfezdyg" ascii
    $s3  = "awyktuqrejfaxjivnukpofygybesxidahdimuhhorasjonmyswejsunaxhabjykqujagqafymogetkiqmivjexagalsawzumavxikavkirqyqdubgiwenuqhiqnyhsak" ascii
    $s4  = "true, true, \"onk174arog\", \"sba827focqy\"][4][1] + [\"yw902vrafo\", [\"sjej363yj\", \"Get\"], \"otweb300ur\", true, true, true" ascii
    $s5  = "lbexanoqxuhulkefygredfofvuwulpejubmaqepwubugekcoxjaxigfeqihqemzasmukfarxehfeklecqehitijacbebazlupyzipivygapiresnurrukykconfezdyg" ascii
    $s6  = "true, \"Get\"], \"ujze141pevh\", \"ig689dizve\", \"uksy106ehomx\", \"udy610kxybp\", \"edu714ema\", \"yl885pki\", \"axl118bbuc\"]" ascii
    $s7  = "lbexanoqxuhulkefygredfofvuwulpejubmaqepwubugekcoxjaxigfeqihqemzasmukfarxehfeklecqehitijacbebazlupyzipivygapiresnurrukykconfezdyg" ascii
    $s8  = "71pinq\", \"am244umev\", \"hid870ikyr\", \"qwo177xgir\", \"vcomz310nahu\", \"acr767ykn\"][1][0] + [\"ibcy566yxub\", [true, \"ar3" ascii
    $s9  = "koqpocullapykyjajwydohzapuvtigxumovpuqompodcygaxvijdyxanrokubhetwustalzorzafzummiwfilpimagyciserjehcunfijutizvybvafamsibjacyghyz" ascii
    $s10 = "exusdyhqopygfixugyjnurcytreqdasirgarcukafixbowdumrevmehahykussycvukunozhudhynyvtumifjufopicackumbopmohesrobjebomzyxxyqmuhetryhot" ascii
    $s11 = "\"ljiksy407uc\", true, [\"GET\", true], true, true, \"enun517dolx\", \"fyxgo563onwun\", \"mdus249pxala\", true, \"dhacd549se\", " ascii
    $s12 = " [\"sjo544ptuhcy\", \"omyc660ukud\", [\"exe\", true, \"ibaff359ytt\"], \"glogpe368seg\", \"oq528ha\", \"fafje478toc\", true, \"y" ascii
    $s13 = "gyciserjehcunfijutizvybvafamsibjacyghyzgixetepetigdiduguvbeqgapzespywagakimesan1[[\"pul268sqy\", true, [\"ickegk713vosi\", true," ascii
    $s14 = "awyktuqrejfaxjivnukpofygybesxidahdimuhhorasjonmyswejsunaxhabjykqujagqafymogetkiqmivjexagalsawzumavxikavkirqyqdubgiwenuqhiqnyhsak" ascii
    $s15 = "if ([true, new Function([\"gaqz867ih\", [\"if(\", \"eqo946aje\"], \"rjizm736ty\", \"nu420hy\", true, \"ysr277abk\", \"im995bdile" ascii
    $s16 = "lbexanoqxuhulkefygredfofvuwulpejubmaqepwubugekcoxjaxigfeqihqemzasmukfarxehfeklecqehitijacbebazlupyzipivygapiresnurrukykconfezdyg" ascii
    $s17 = "lbexanoqxuhulkefygredfofvuwulpejubmaqepwubugekcoxjaxigfeqihqemzasmukfarxehfeklecqehitijacbebazlupyzipivygapiresnurrukykconfezdyg" ascii
    $s18 = "edkeddamlanibalyrfygaritsawhusdyqlapmazuvdyfnehxatkoctokybidwommajenfajaruslevgysqagxaxmyholylfezahwivhehyfzilisydveznupjesuzahw" ascii
    $s19 = "uhufsonaloqdifzenydyzelmurirxukezkandyqseqlukdegawsisvytelsopewyhsiwvuvenronijpahtazdutb7[[[true, \"Get\", true], \"xrew867dig\"" ascii
    $s20 = "o\"], \"kak951tavc\", true, true, true, \"hla569dke\", \"ujiqd883xvu\", \"yt970kxejza\", \"izp831bji\", \"roml852arat\", \"avwyq" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}