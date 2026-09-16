rule TTP_XOR_QUAD_CurrentVersionRun_1f30 {
  strings:
    $key_1f30 = { 4c 5f [2] 68 51 [2] 43 7d [2] 6d 5f [2] 79 44 [2] 76 5e [2] 68 43 [2] 6a 42 [2] 71 44 [2] 6d 43 [2] 71 6c }

  condition:
    any of them
}