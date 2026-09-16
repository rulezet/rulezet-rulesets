rule TTP_XOR_QUAD_CurrentVersionRun_0200 {
  strings:
    $key_0200 = { 51 6f [2] 75 61 [2] 5e 4d [2] 70 6f [2] 64 74 [2] 6b 6e [2] 75 73 [2] 77 72 [2] 6c 74 [2] 70 73 [2] 6c 5c }

  condition:
    any of them
}