rule TTP_XOR_QUAD_CurrentVersionRun_0430 {
  strings:
    $key_0430 = { 57 5f [2] 73 51 [2] 58 7d [2] 76 5f [2] 62 44 [2] 6d 5e [2] 73 43 [2] 71 42 [2] 6a 44 [2] 76 43 [2] 6a 6c }

  condition:
    any of them
}