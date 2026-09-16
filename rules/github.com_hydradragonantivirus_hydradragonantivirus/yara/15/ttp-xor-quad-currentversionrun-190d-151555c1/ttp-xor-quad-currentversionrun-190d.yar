rule TTP_XOR_QUAD_CurrentVersionRun_190d {
  strings:
    $key_190d = { 4a 62 [2] 6e 6c [2] 45 40 [2] 6b 62 [2] 7f 79 [2] 70 63 [2] 6e 7e [2] 6c 7f [2] 77 79 [2] 6b 7e [2] 77 51 }

  condition:
    any of them
}