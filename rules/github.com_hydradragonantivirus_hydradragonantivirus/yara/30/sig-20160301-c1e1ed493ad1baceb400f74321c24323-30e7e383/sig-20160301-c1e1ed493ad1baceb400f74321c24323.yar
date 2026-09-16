rule sig_20160301_c1e1ed493ad1baceb400f74321c24323 {
  meta:
    description = "datamaliciousorder - file 20160301_c1e1ed493ad1baceb400f74321c24323.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9d7c2da3f01d59ffa31649178ac69867c791b79aa4a3dd4fbc7670ee7ea9c6b"

  strings:
    $s1 = "operationCircle = (((99 - 66), (36 | 69), (13 ^ 150)), this);" fullword ascii
    $s2 = "while (artilleryContrast[(\"rea\\u0064ysta\\u0074\\u0065\")] < ((0 + 0) | (37 - 33))) {" fullword ascii
    $s3 = "artilleryContrast[(\"a\\u006e\\u0061l\\u006f\\u0067\\u0079\", function String.prototype.symptomAmorphous() {" fullword ascii
    $s4 = "} catch (accordNose) {};" fullword ascii

  condition:
    uint16(0) == 0x706f and
    all of them
}