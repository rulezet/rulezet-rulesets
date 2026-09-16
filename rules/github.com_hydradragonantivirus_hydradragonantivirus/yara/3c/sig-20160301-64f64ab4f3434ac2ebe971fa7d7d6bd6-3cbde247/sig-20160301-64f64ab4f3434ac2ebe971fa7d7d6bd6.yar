rule sig_20160301_64f64ab4f3434ac2ebe971fa7d7d6bd6 {
  meta:
    description = "datamaliciousorder - file 20160301_64f64ab4f3434ac2ebe971fa7d7d6bd6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f234364e892faa21c9001425e5357bad77aa2e4426cabf2936c973ad5e7b9f4"

  strings:
    $x1 = "cylinderInformer = finishArbiter[(\"sponsor\", \"postscript\", \"ExpandEnvironmentStrings\")]((\"variant\", \"scalpel\", \"artic" ascii
    $s2 = "cylinderInformer = finishArbiter[(\"sponsor\", \"postscript\", \"ExpandEnvironmentStrings\")]((\"variant\", \"scalpel\", \"artic" ascii
    $s3 = "while (intellectReport[(\"spindle\", \"television\", \"readystate\")] < ((([!+[] + !+[]])) * (1 * 2))) {" fullword ascii
    $s4 = "attributeAgent = patrolLegend[(\"passive\", function String.prototype.regionAmphibian() {" fullword ascii
    $s5 = "patrolLegend = (((147, 111, 218, 188)), this);" fullword ascii
    $s6 = "} catch (assemblyChaos) {};" fullword ascii

  condition:
    uint16(0) == 0x6170 and
    1 of ($x*) and all of them
}