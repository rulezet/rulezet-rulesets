rule TTP_XOR_QUAD_CurrentVersionRun_6c02 {
  strings:
    $key_6c02 = { 3f 6d [2] 1b 63 [2] 30 4f [2] 1e 6d [2] 0a 76 [2] 05 6c [2] 1b 71 [2] 19 70 [2] 02 76 [2] 1e 71 [2] 02 5e }

  condition:
    any of them
}