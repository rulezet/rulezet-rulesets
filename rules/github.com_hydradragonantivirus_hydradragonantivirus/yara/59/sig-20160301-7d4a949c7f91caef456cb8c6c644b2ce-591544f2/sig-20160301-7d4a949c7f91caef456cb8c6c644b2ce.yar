rule sig_20160301_7d4a949c7f91caef456cb8c6c644b2ce {
  meta:
    description = "datamaliciousorder - file 20160301_7d4a949c7f91caef456cb8c6c644b2ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94ef1ec27607ac159a6396ac3d1895539fd763e582cac80127fb68c3d83b43dc"

  strings:
    $s1 = "while (operatorVoyage[(\"\\u0074h\\u0065o\" + \"r\" + \"\\u0065\\u006d\", \"r\\u0065\\u0061\" + \"\\u0064\" + \"\\u0079s\\u0074a" ascii
    $s2 = "operatorVoyage[(\"\\u0072\\u0061di\" + \"ca\" + \"\\u006c\", function String.prototype.apostropheComputer() {" fullword ascii
    $s3 = "while (operatorVoyage[(\"\\u0074h\\u0065o\" + \"r\" + \"\\u0065\\u006d\", \"r\\u0065\\u0061\" + \"\\u0064\" + \"\\u0079s\\u0074a" ascii
    $s4 = "frontDialect = ((39 - 38), this);" fullword ascii
    $s5 = "} catch (typeVulgar) {};" fullword ascii

  condition:
    uint16(0) == 0x7266 and
    all of them
}