rule _20160831_97d20ea97caa1e84d9b9cf55ed4369eb_20160831_e27f302bd7ea_180 {
  meta:
    description = "datamaliciousorder - from files 20160831_97d20ea97caa1e84d9b9cf55ed4369eb.js, 20160831_e27f302bd7eab43216d00e804cbf5139.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6c813b5524282a10ba1041434a0f0e82857317d424e19ad773a7a440bd32792"
    hash2       = "6c5380494e435105c080c5141e1391fc7906b54e33878fb68eb2b126f2c069e4"

  strings:
    $s1 = "aver!!!!!!Kjshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!OEishut-the-fuck-up-motherfucki" ascii
    $s2 = "aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!DLr7shut-the-fuck-up-motherfu" ascii
    $s3 = "aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!OEishut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucki" ascii
    $s4 = "aver!!!!!!Eeshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucki" ascii
    $s5 = "aver!!!!!!ASy5shut-the-fuck-up-motherfucking-aver!!!!!!Dy2shut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfu" ascii

  condition:
    (uint16(0) == 0x7566 and (all of them)
    ) or (all of them)
}