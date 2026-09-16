rule TTP_XOR_QUAD_CurrentVersionRun_5080 {
  strings:
    $key_5080 = { 03 ef [2] 27 e1 [2] 0c cd [2] 22 ef [2] 36 f4 [2] 39 ee [2] 27 f3 [2] 25 f2 [2] 3e f4 [2] 22 f3 [2] 3e dc }

  condition:
    any of them
}