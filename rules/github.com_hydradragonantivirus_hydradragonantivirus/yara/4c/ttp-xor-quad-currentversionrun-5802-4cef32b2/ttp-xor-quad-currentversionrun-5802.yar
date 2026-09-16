rule TTP_XOR_QUAD_CurrentVersionRun_5802 {
  strings:
    $key_5802 = { 0b 6d [2] 2f 63 [2] 04 4f [2] 2a 6d [2] 3e 76 [2] 31 6c [2] 2f 71 [2] 2d 70 [2] 36 76 [2] 2a 71 [2] 36 5e }

  condition:
    any of them
}