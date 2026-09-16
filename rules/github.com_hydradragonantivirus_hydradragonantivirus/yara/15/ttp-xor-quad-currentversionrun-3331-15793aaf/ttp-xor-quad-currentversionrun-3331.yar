rule TTP_XOR_QUAD_CurrentVersionRun_3331 {
  strings:
    $key_3331 = { 60 5e [2] 44 50 [2] 6f 7c [2] 41 5e [2] 55 45 [2] 5a 5f [2] 44 42 [2] 46 43 [2] 5d 45 [2] 41 42 [2] 5d 6d }

  condition:
    any of them
}