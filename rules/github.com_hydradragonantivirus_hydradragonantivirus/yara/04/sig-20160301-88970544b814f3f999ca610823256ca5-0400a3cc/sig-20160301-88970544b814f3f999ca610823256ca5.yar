rule sig_20160301_88970544b814f3f999ca610823256ca5 {
  meta:
    description = "datamaliciousorder - file 20160301_88970544b814f3f999ca610823256ca5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94f674cf64a8559d0e30c89d6a26808de71c384d5091a0189d1a803266884d59"

  strings:
    $s1 = "negativeAssistant = (((Math.pow(115, 2) - 13087), (Math.pow(85, 2) - 7059), (Math.pow(352, 2) - 123730), (Math.pow(412, 2) - 169" ascii
    $s2 = "while(tamponPress[(\"o\\u0066\\u0066\\u0069cial\", \"\\u006du\\u0073\\u0069\\u0063\", \"\\u0072\\u0065a\\u0064\\u0079\\u0073ta" ascii
    $s3 = "while(tamponPress[(\"o\\u0066\\u0066\\u0069cial\", \"\\u006du\\u0073\\u0069\\u0063\", \"\\u0072\\u0065a\\u0064\\u0079\\u0073ta" ascii
    $s4 = "tamponPress = negativeAssistant[(\"chance\", function String.prototype.saturationCursive() {" fullword ascii
    $s5 = "503)), this);" fullword ascii
    $s6 = "} catch(sandwichFocus) {};" fullword ascii

  condition:
    uint16(0) == 0x656e and
    all of them
}