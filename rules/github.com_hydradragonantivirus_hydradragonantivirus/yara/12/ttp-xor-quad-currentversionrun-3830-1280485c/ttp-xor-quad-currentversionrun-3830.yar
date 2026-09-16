rule TTP_XOR_QUAD_CurrentVersionRun_3830 {
  strings:
    $key_3830 = { 6b 5f [2] 4f 51 [2] 64 7d [2] 4a 5f [2] 5e 44 [2] 51 5e [2] 4f 43 [2] 4d 42 [2] 56 44 [2] 4a 43 [2] 56 6c }

  condition:
    any of them
}