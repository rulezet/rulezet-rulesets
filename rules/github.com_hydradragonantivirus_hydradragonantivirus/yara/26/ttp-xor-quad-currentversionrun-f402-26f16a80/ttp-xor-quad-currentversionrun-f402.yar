rule TTP_XOR_QUAD_CurrentVersionRun_f402 {
  strings:
    $key_f402 = { a7 6d [2] 83 63 [2] a8 4f [2] 86 6d [2] 92 76 [2] 9d 6c [2] 83 71 [2] 81 70 [2] 9a 76 [2] 86 71 [2] 9a 5e }

  condition:
    any of them
}