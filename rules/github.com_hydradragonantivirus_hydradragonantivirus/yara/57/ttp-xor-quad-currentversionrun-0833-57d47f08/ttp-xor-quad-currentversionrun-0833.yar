rule TTP_XOR_QUAD_CurrentVersionRun_0833 {
  strings:
    $key_0833 = { 5b 5c [2] 7f 52 [2] 54 7e [2] 7a 5c [2] 6e 47 [2] 61 5d [2] 7f 40 [2] 7d 41 [2] 66 47 [2] 7a 40 [2] 66 6f }

  condition:
    any of them
}