rule TTP_XOR_QUAD_CurrentVersionRun_1402 {
  strings:
    $key_1402 = { 47 6d [2] 63 63 [2] 48 4f [2] 66 6d [2] 72 76 [2] 7d 6c [2] 63 71 [2] 61 70 [2] 7a 76 [2] 66 71 [2] 7a 5e }

  condition:
    any of them
}