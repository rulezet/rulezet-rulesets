rule TTP_XOR_QUAD_CurrentVersionRun_3c9d {
  strings:
    $key_3c9d = { 6f f2 [2] 4b fc [2] 60 d0 [2] 4e f2 [2] 5a e9 [2] 55 f3 [2] 4b ee [2] 49 ef [2] 52 e9 [2] 4e ee [2] 52 c1 }

  condition:
    any of them
}