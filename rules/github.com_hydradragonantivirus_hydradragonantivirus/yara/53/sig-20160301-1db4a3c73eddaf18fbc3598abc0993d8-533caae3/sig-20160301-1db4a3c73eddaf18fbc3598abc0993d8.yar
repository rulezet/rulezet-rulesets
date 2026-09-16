rule sig_20160301_1db4a3c73eddaf18fbc3598abc0993d8 {
  meta:
    description = "datamaliciousorder - file 20160301_1db4a3c73eddaf18fbc3598abc0993d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "409a08dab76b88c6a0c79febdc071bdd96f847115d552f9bd28fef21719d6ec2"

  strings:
    $s1 = "materialSkeleton = packetPacking[(\"decade\", \"ExpandEnvironmentStrings\")]((\"guest\", \"%TEMP%/\")) + (\"collection\", \"huma" ascii
    $s2 = "apparatusAutonomous = ((Math.pow((105 ^ 342), (([!+[] + !+[]]))) - (14032 * 7 + 3267)), this);" fullword ascii
    $s3 = "materialSkeleton = packetPacking[(\"decade\", \"ExpandEnvironmentStrings\")]((\"guest\", \"%TEMP%/\")) + (\"collection\", \"huma" ascii
    $s4 = "while(penaltyContribution[(\"genealogy\", \"organ\", \"decade\", \"sponsor\", \"readystate\")] < ((0 | 0) + (0 ^ 4))) {" fullword ascii
    $s5 = "spherePassion[(\"museum\", function String.prototype.portFinal() {" fullword ascii
    $s6 = "} catch(balloonTrajectory) {};" fullword ascii

  condition:
    uint16(0) == 0x7061 and
    all of them
}