rule TTP_XOR_QUAD_CurrentVersionRun_3745 {
  strings:
    $key_3745 = { 64 2a [2] 40 24 [2] 6b 08 [2] 45 2a [2] 51 31 [2] 5e 2b [2] 40 36 [2] 42 37 [2] 59 31 [2] 45 36 [2] 59 19 }

  condition:
    any of them
}