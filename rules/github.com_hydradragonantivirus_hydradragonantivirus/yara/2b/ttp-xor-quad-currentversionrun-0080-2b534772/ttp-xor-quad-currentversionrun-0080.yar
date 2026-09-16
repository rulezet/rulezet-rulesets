rule TTP_XOR_QUAD_CurrentVersionRun_0080 {
  strings:
    $key_0080 = { 53 ef [2] 77 e1 [2] 5c cd [2] 72 ef [2] 66 f4 [2] 69 ee [2] 77 f3 [2] 75 f2 [2] 6e f4 [2] 72 f3 [2] 6e dc }

  condition:
    any of them
}