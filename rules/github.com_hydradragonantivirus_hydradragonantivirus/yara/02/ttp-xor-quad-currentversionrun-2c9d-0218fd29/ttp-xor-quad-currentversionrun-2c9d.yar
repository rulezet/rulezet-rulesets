rule TTP_XOR_QUAD_CurrentVersionRun_2c9d {
  strings:
    $key_2c9d = { 7f f2 [2] 5b fc [2] 70 d0 [2] 5e f2 [2] 4a e9 [2] 45 f3 [2] 5b ee [2] 59 ef [2] 42 e9 [2] 5e ee [2] 42 c1 }

  condition:
    any of them
}