rule TTP_XOR_QUAD_CurrentVersionRun_3601 {
  strings:
    $key_3601 = { 65 6e [2] 41 60 [2] 6a 4c [2] 44 6e [2] 50 75 [2] 5f 6f [2] 41 72 [2] 43 73 [2] 58 75 [2] 44 72 [2] 58 5d }

  condition:
    any of them
}