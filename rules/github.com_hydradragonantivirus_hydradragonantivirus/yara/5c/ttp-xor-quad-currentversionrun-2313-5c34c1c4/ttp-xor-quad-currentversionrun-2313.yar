rule TTP_XOR_QUAD_CurrentVersionRun_2313 {
  strings:
    $key_2313 = { 70 7c [2] 54 72 [2] 7f 5e [2] 51 7c [2] 45 67 [2] 4a 7d [2] 54 60 [2] 56 61 [2] 4d 67 [2] 51 60 [2] 4d 4f }

  condition:
    any of them
}