rule TTP_XOR_QUAD_CurrentVersionRun_0563 {
  strings:
    $key_0563 = { 56 0c [2] 72 02 [2] 59 2e [2] 77 0c [2] 63 17 [2] 6c 0d [2] 72 10 [2] 70 11 [2] 6b 17 [2] 77 10 [2] 6b 3f }

  condition:
    any of them
}