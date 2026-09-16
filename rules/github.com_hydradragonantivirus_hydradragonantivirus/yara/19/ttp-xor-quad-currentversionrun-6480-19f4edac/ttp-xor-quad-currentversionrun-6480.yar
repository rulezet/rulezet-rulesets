rule TTP_XOR_QUAD_CurrentVersionRun_6480 {
  strings:
    $key_6480 = { 37 ef [2] 13 e1 [2] 38 cd [2] 16 ef [2] 02 f4 [2] 0d ee [2] 13 f3 [2] 11 f2 [2] 0a f4 [2] 16 f3 [2] 0a dc }

  condition:
    any of them
}