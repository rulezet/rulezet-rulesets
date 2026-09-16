rule TTP_XOR_QUAD_CurrentVersionRun_3e11 {
  strings:
    $key_3e11 = { 6d 7e [2] 49 70 [2] 62 5c [2] 4c 7e [2] 58 65 [2] 57 7f [2] 49 62 [2] 4b 63 [2] 50 65 [2] 4c 62 [2] 50 4d }

  condition:
    any of them
}