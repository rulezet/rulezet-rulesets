rule TTP_XOR_QUAD_CurrentVersionRun_6fd2 {
  strings:
    $key_6fd2 = { 3c bd [2] 18 b3 [2] 33 9f [2] 1d bd [2] 09 a6 [2] 06 bc [2] 18 a1 [2] 1a a0 [2] 01 a6 [2] 1d a1 [2] 01 8e }

  condition:
    any of them
}