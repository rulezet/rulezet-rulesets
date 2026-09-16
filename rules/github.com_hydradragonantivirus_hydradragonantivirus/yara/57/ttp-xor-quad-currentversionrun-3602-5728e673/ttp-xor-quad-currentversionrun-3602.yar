rule TTP_XOR_QUAD_CurrentVersionRun_3602 {
  strings:
    $key_3602 = { 65 6d [2] 41 63 [2] 6a 4f [2] 44 6d [2] 50 76 [2] 5f 6c [2] 41 71 [2] 43 70 [2] 58 76 [2] 44 71 [2] 58 5e }

  condition:
    any of them
}