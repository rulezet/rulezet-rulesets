rule TTP_XOR_QUAD_CurrentVersionRun_1b02 {
  strings:
    $key_1b02 = { 48 6d [2] 6c 63 [2] 47 4f [2] 69 6d [2] 7d 76 [2] 72 6c [2] 6c 71 [2] 6e 70 [2] 75 76 [2] 69 71 [2] 75 5e }

  condition:
    any of them
}