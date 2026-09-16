rule sig_20160301_7733fc4b8a73cd80b82c066ae4f0fdd3 {
  meta:
    description = "datamaliciousorder - file 20160301_7733fc4b8a73cd80b82c066ae4f0fdd3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63bdd7a13248bccfa5132c879d2ced7e82ce91b8a9c9b560d68e51625baa57c9"

  strings:
    $s1 = "diagramComment = (((553 - 291) | (1 + 9)), this);" fullword ascii
    $s2 = "processRadical = hallPrologue[(\"ma\\u006e\\u0075sc\\u0072\\u0069\\u0070\\u0074\", \"h\\u006fs\\u0070i\\u0074\\u0061l\", \"\\u00" ascii
    $s3 = "while(dictatorMethod[(\"m\\u006fdal\", \"p\\u0065r\\u0069od\", \"e\\u0078\\u0061\\u006d\\u0069n\\u0061\\u0074ion\", \"s\\u0075" ascii
    $s4 = "6f\\u0072\", \"d\\u0061\\u0074e\", function String.prototype.metalResidence() {" fullword ascii
    $s5 = "while(dictatorMethod[(\"m\\u006fdal\", \"p\\u0065r\\u0069od\", \"e\\u0078\\u0061\\u006d\\u0069n\\u0061\\u0074ion\", \"s\\u0075" ascii
    $s6 = "} catch(canalMedical) {};" fullword ascii

  condition:
    uint16(0) == 0x6964 and
    all of them
}