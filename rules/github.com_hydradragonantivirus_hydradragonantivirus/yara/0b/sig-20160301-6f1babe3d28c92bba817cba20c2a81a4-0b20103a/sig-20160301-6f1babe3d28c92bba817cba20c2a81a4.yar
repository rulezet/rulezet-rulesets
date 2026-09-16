rule sig_20160301_6f1babe3d28c92bba817cba20c2a81a4 {
  meta:
    description = "datamaliciousorder - file 20160301_6f1babe3d28c92bba817cba20c2a81a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18c74a3f6f6eb7a5b3a4e1a91b460927c4def657a0a85f7d00d4aa2d765501ff"

  strings:
    $s1 = "while(netCocoon[(\"mo\\u0064e\" + \"rn\", \"\\u0063\\u006fnt\\u0061\" + \"\\u0069\\u006eer\", \"activ\" + \"e\", \"\\u0072e\" + " ascii
    $s2 = "while(netCocoon[(\"mo\\u0064e\" + \"rn\", \"\\u0063\\u006fnt\\u0061\" + \"\\u0069\\u006eer\", \"activ\" + \"e\", \"\\u0072e\" + " ascii
    $s3 = "contributionCensor = (((8 * 2 + 2), (96 + 93), (([+!+[]]))), this);" fullword ascii
    $s4 = "firmSolid = textAbsorption[(\"ac\\u0063u\\u006d\" + \"\\u0075\\u006c\\u0061t\" + \"\\u006f\\u0072\", \"\\u0073t\\u0061ti\" + \"s" ascii
    $s5 = "} catch(attractionClass) {};" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    all of them
}