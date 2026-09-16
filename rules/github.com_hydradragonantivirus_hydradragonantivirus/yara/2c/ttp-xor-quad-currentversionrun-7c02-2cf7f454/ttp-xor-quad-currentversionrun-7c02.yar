rule TTP_XOR_QUAD_CurrentVersionRun_7c02 {
  strings:
    $key_7c02 = { 2f 6d [2] 0b 63 [2] 20 4f [2] 0e 6d [2] 1a 76 [2] 15 6c [2] 0b 71 [2] 09 70 [2] 12 76 [2] 0e 71 [2] 12 5e }

  condition:
    any of them
}