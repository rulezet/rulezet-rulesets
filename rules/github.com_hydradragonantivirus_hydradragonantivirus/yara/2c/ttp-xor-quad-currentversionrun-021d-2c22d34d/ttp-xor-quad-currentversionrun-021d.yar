rule TTP_XOR_QUAD_CurrentVersionRun_021d {
  strings:
    $key_021d = { 51 72 [2] 75 7c [2] 5e 50 [2] 70 72 [2] 64 69 [2] 6b 73 [2] 75 6e [2] 77 6f [2] 6c 69 [2] 70 6e [2] 6c 41 }

  condition:
    any of them
}