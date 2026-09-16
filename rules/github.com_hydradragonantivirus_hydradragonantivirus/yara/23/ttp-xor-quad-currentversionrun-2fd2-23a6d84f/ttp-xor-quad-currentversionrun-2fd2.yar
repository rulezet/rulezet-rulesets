rule TTP_XOR_QUAD_CurrentVersionRun_2fd2 {
  strings:
    $key_2fd2 = { 7c bd [2] 58 b3 [2] 73 9f [2] 5d bd [2] 49 a6 [2] 46 bc [2] 58 a1 [2] 5a a0 [2] 41 a6 [2] 5d a1 [2] 41 8e }

  condition:
    any of them
}