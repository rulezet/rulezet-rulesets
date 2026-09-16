rule TTP_XOR_QUAD_CurrentVersionRun_0f33 {
  strings:
    $key_0f33 = { 5c 5c [2] 78 52 [2] 53 7e [2] 7d 5c [2] 69 47 [2] 66 5d [2] 78 40 [2] 7a 41 [2] 61 47 [2] 7d 40 [2] 61 6f }

  condition:
    any of them
}