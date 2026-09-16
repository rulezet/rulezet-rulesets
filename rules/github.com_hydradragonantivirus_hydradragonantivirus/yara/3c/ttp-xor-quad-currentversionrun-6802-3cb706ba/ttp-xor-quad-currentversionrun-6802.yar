rule TTP_XOR_QUAD_CurrentVersionRun_6802 {
  strings:
    $key_6802 = { 3b 6d [2] 1f 63 [2] 34 4f [2] 1a 6d [2] 0e 76 [2] 01 6c [2] 1f 71 [2] 1d 70 [2] 06 76 [2] 1a 71 [2] 06 5e }

  condition:
    any of them
}