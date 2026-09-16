rule TTP_XOR_QUAD_CurrentVersionRun_111d {
  strings:
    $key_111d = { 42 72 [2] 66 7c [2] 4d 50 [2] 63 72 [2] 77 69 [2] 78 73 [2] 66 6e [2] 64 6f [2] 7f 69 [2] 63 6e [2] 7f 41 }

  condition:
    any of them
}