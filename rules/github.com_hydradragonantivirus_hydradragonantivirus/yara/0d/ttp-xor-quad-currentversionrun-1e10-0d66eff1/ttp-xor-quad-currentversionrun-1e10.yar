rule TTP_XOR_QUAD_CurrentVersionRun_1e10 {
  strings:
    $key_1e10 = { 4d 7f [2] 69 71 [2] 42 5d [2] 6c 7f [2] 78 64 [2] 77 7e [2] 69 63 [2] 6b 62 [2] 70 64 [2] 6c 63 [2] 70 4c }

  condition:
    any of them
}