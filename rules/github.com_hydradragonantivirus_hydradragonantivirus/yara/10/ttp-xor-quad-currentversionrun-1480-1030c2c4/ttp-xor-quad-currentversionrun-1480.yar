rule TTP_XOR_QUAD_CurrentVersionRun_1480 {
  strings:
    $key_1480 = { 47 ef [2] 63 e1 [2] 48 cd [2] 66 ef [2] 72 f4 [2] 7d ee [2] 63 f3 [2] 61 f2 [2] 7a f4 [2] 66 f3 [2] 7a dc }

  condition:
    any of them
}