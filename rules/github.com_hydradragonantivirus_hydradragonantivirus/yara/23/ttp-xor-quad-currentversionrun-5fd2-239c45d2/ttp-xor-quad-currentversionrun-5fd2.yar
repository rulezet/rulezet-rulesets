rule TTP_XOR_QUAD_CurrentVersionRun_5fd2 {
  strings:
    $key_5fd2 = { 0c bd [2] 28 b3 [2] 03 9f [2] 2d bd [2] 39 a6 [2] 36 bc [2] 28 a1 [2] 2a a0 [2] 31 a6 [2] 2d a1 [2] 31 8e }

  condition:
    any of them
}