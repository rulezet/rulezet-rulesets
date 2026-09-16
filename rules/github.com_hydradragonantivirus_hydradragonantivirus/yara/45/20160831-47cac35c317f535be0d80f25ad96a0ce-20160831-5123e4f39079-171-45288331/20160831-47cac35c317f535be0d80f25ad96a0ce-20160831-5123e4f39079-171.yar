rule _20160831_47cac35c317f535be0d80f25ad96a0ce_20160831_5123e4f39079_171 {
  meta:
    description = "datamaliciousorder - from files 20160831_47cac35c317f535be0d80f25ad96a0ce.js, 20160831_5123e4f390793713e3327b82ae3ed8ed.js, 20160831_5f5a7bd1c4282c968efb82785470aeb8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "418178b5c34246775d9ec21125111981452f7beb5d84fc2ab09b2bc5adb770e3"
    hash2       = "54aa230bbee94b286e65dead9bf89a717a7ba9cfaacc6e9da0d0fc82ccff1c71"
    hash3       = "72b5959289b02dc15e5ee3322f5ed84ab7e2828e59342c0a4b665922b6836070"

  strings:
    $s1 = "aver!!!!!!DLr7shut-the-fuck-up-motherfucking-aver!!!!!!OEishut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuck" ascii
    $s2 = "aver!!!!!!OEishut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s3 = "aver!!!!!!GRc7shut-the-fuck-up-motherfucking-aver!!!!!!DBa4shut-the-fuck-up-motherfucking-aver!!!!!!Gcshut-the-fuck-up-motherfuc" ascii
    $s4 = "aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!Ck3shut-the-fuck-up-motherfucking-aver!!!!!!Noshut-the-fuck-up-motherfuckin" ascii
    $s5 = "aver!!!!!!NEbshut-the-fuck-up-motherfucking-aver!!!!!!LYk5shut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfuck" ascii
    $s6 = "aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!Rnshut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfucking" ascii

  condition:
    (uint16(0) == 0x7566 and (all of them)
    ) or (all of them)
}