rule TTP_XOR_QUAD_CurrentVersionRun_2480 {
  strings:
    $key_2480 = { 77 ef [2] 53 e1 [2] 78 cd [2] 56 ef [2] 42 f4 [2] 4d ee [2] 53 f3 [2] 51 f2 [2] 4a f4 [2] 56 f3 [2] 4a dc }

  condition:
    any of them
}