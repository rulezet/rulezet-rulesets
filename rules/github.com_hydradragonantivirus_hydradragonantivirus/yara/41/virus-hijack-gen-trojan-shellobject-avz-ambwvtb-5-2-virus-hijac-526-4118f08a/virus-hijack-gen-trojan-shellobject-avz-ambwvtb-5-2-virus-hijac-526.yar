rule _Virus_Hijack_Gen_Trojan_ShellObject_avZ_amBwvTb_5_2_Virus_Hijac_526 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.avZ@amBwvTb_5_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.eGY@augxLYc_19_2.vir, VirusShareBackDoorMeterpreter216.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b10b1c0f9218bf974fccbeda602c823502f9927174b22df53db4f1a7daf67ffc"
    hash2       = "5ed907dbad20604899e87d9da0e41f1a3e87cba9d93533f736d0ef9f28639340"
    hash3       = "2209ac09da78031d7bdcd91b05041e41a2dcbd0f2c842aa839ba3d18480e2c01"

  strings:
    $s1 = "bad defer entry in panicbad defer size class: i=bypassed recovery failedcan't scan our own stackconnection reset by peerdouble t" ascii
    $s2 = "object is remotepacer: H_m_prev=reflect mismatchremote I/O errorruntime:  g:  g=runtime: addr = runtime: base = runtime: gp: gp=" ascii
    $s3 = "ChunkBytesP has cached GC work at end of mark terminationattempting to link in too many shared librariesracy sudog adjustment du" ascii
    $s4 = "morebuf={pc:advertise errorasyncpreemptoffforce gc (idle)key has expiredmalloc deadlockmisaligned maskmissing mcache?ms: gomaxpr" ascii
    $s5 = " lockedg= lockedm= m->curg= marked   ms cpu,  not in [ runtime= s.limit= s.state= threads= u_a/u_g= unmarked wbuf1.n= wbuf2.n=(u" ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}