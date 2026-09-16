rule TTP_XOR_QUAD_CurrentVersionRun_4402 {
  strings:
    $key_4402 = { 17 6d [2] 33 63 [2] 18 4f [2] 36 6d [2] 22 76 [2] 2d 6c [2] 33 71 [2] 31 70 [2] 2a 76 [2] 36 71 [2] 2a 5e }

  condition:
    any of them
}