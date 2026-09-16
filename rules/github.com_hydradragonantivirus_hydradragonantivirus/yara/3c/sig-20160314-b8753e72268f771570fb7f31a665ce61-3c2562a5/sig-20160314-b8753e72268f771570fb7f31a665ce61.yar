rule sig_20160314_b8753e72268f771570fb7f31a665ce61 {
  meta:
    description = "datamaliciousorder - file 20160314_b8753e72268f771570fb7f31a665ce61.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b7adceae37fa57ede8536d7dcd3f2052f631ef8c1a4a059c9d9a26a51fe7c56"

  strings:
    $s1 = "WakDtEMwMcHmBH.open(xnFmuNBKaN, ZbP + CfGLuAyg + IcRVdoij + NPUHNMC + nIXNDLVbAaagnV + EXirLAA + WebjgohqjIEmjXb + yEfvuHkoAbRKd" ascii
    $s2 = "while (WakDtEMwMcHmBH.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = " + PejHqEBYaSbb + YAMzGsGdQoUMYy + BFBV + LiaHOrrTEvWYcw + BwCK + xGUAAZ + DBSUbpJCOd + twuJoHjm, false);" fullword ascii
    $s4 = "return jhgCunOqGd + HiPgphmO + CdaqwvplwXYmuRW + vQaqwpCst + NUhQDpkln + LSwwQsx + UjlMfAmREz + IGl" fullword ascii
    $s5 = "var JipChWIsqBHwyQ = new Date();" fullword ascii
    $s6 = "function wmgSgavobkZizh(n)" fullword ascii
    $s7 = "function iYF(fname)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}