rule sig_20160301_8fc01db39058b377e2eafa2fd7d8acfa {
  meta:
    description = "datamaliciousorder - file 20160301_8fc01db39058b377e2eafa2fd7d8acfa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7ffa87087c5c6169a817a668838aae5ab68f50652136409a764c8395a13b9ed"

  strings:
    $s1 = "062\" + \"\\u006a\" + \"\\u0065\\u0063\" + \"\\u0074\")]((\"\\u0070\\u0061\\u0072a\" + \"gr\\u0061p\\u0068\", function String.pr" ascii
    $s2 = "while (ideaContact[(\"vac\" + \"uum\", \"s\\u0074a\\u0074i\" + \"\\u006f\\u006e\", \"\\u0069l\\u006c\\u0075\\u0073t\" + \"r\\u00" ascii
    $s3 = "while (ideaContact[(\"vac\" + \"uum\", \"s\\u0074a\\u0074i\" + \"\\u006f\\u006e\", \"\\u0069l\\u006c\\u0075\\u0073t\" + \"r\\u00" ascii
    $s4 = "procedureReform = (((9 / 9) ^ (191, 170, 103, 0)), this);" fullword ascii
    $s5 = "ideaContact = procedureReform[(\"\\u0061c\" + \"\\u0074\", \"\\u0065pi\" + \"l\\u006fgue\", \"l\" + \"o\" + \"\\u0063a\\u0074io" ascii
    $s6 = "} catch (techniqueEcho) {};" fullword ascii

  condition:
    uint16(0) == 0x7270 and
    all of them
}