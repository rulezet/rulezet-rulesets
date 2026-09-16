rule TTP_XOR_QUAD_CurrentVersionRun_2301 {
  strings:
    $key_2301 = { 70 6e [2] 54 60 [2] 7f 4c [2] 51 6e [2] 45 75 [2] 4a 6f [2] 54 72 [2] 56 73 [2] 4d 75 [2] 51 72 [2] 4d 5d }

  condition:
    any of them
}