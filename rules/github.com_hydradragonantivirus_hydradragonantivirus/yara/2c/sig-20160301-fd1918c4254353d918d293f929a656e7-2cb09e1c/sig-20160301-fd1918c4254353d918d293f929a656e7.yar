rule sig_20160301_fd1918c4254353d918d293f929a656e7 {
  meta:
    description = "datamaliciousorder - file 20160301_fd1918c4254353d918d293f929a656e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b5df47028685eec0bc8fc71d319a855086a397ce2c161a73b80a96e0cd684dc"

  strings:
    $s1 = "revisionInstance = ((1 & (11 - 10)), this);" fullword ascii
    $s2 = "realizationVisa[(\"\\u0064ic\" + \"ta\" + \"t\\u006fr\", \"\\u0061nat\\u006f\\u006d\" + \"\\u0079\", function String.prototype.i" ascii
    $s3 = "while(absurdIndividual[(\"\\u0063\\u006f\\u006c\\u006c\\u0065c\" + \"t\", \"li\\u0074e\" + \"ra\\u0074u\\u0072\" + \"e\", \"r\\u" ascii
    $s4 = "realizationVisa[(\"\\u0064ic\" + \"ta\" + \"t\\u006fr\", \"\\u0061nat\\u006f\\u006d\" + \"\\u0079\", function String.prototype.i" ascii
    $s5 = "while(absurdIndividual[(\"\\u0063\\u006f\\u006c\\u006c\\u0065c\" + \"t\", \"li\\u0074e\" + \"ra\\u0074u\\u0072\" + \"e\", \"r\\u" ascii
    $s6 = "} catch(bufferAssortment) {};" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    all of them
}