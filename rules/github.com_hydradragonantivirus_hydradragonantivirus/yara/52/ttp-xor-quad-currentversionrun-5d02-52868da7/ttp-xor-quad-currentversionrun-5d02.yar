rule TTP_XOR_QUAD_CurrentVersionRun_5d02 {
  strings:
    $key_5d02 = { 0e 6d [2] 2a 63 [2] 01 4f [2] 2f 6d [2] 3b 76 [2] 34 6c [2] 2a 71 [2] 28 70 [2] 33 76 [2] 2f 71 [2] 33 5e }

  condition:
    any of them
}