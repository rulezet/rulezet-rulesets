rule TTP_XOR_QUAD_CurrentVersionRun_0530 {
  strings:
    $key_0530 = { 56 5f [2] 72 51 [2] 59 7d [2] 77 5f [2] 63 44 [2] 6c 5e [2] 72 43 [2] 70 42 [2] 6b 44 [2] 77 43 [2] 6b 6c }

  condition:
    any of them
}