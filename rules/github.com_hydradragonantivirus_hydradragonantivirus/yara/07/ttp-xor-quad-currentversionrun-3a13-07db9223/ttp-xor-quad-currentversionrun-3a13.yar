rule TTP_XOR_QUAD_CurrentVersionRun_3a13 {
  strings:
    $key_3a13 = { 69 7c [2] 4d 72 [2] 66 5e [2] 48 7c [2] 5c 67 [2] 53 7d [2] 4d 60 [2] 4f 61 [2] 54 67 [2] 48 60 [2] 54 4f }

  condition:
    any of them
}