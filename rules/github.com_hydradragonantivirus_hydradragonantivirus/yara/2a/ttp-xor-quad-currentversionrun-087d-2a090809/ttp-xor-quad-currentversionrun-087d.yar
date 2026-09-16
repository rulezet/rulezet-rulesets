rule TTP_XOR_QUAD_CurrentVersionRun_087d {
  strings:
    $key_087d = { 5b 12 [2] 7f 1c [2] 54 30 [2] 7a 12 [2] 6e 09 [2] 61 13 [2] 7f 0e [2] 7d 0f [2] 66 09 [2] 7a 0e [2] 66 21 }

  condition:
    any of them
}