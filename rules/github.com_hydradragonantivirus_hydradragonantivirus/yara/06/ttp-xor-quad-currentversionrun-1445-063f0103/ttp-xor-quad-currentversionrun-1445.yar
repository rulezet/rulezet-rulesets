rule TTP_XOR_QUAD_CurrentVersionRun_1445 {
  strings:
    $key_1445 = { 47 2a [2] 63 24 [2] 48 08 [2] 66 2a [2] 72 31 [2] 7d 2b [2] 63 36 [2] 61 37 [2] 7a 31 [2] 66 36 [2] 7a 19 }

  condition:
    any of them
}