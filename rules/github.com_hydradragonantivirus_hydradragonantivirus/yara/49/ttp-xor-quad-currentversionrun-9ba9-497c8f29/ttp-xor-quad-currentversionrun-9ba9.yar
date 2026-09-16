rule TTP_XOR_QUAD_CurrentVersionRun_9ba9 {
  strings:
    $key_9ba9 = { c8 c6 [2] ec c8 [2] c7 e4 [2] e9 c6 [2] fd dd [2] f2 c7 [2] ec da [2] ee db [2] f5 dd [2] e9 da [2] f5 f5 }

  condition:
    any of them
}