rule TTP_XOR_QUAD_CurrentVersionRun_169d {
  strings:
    $key_169d = { 45 f2 [2] 61 fc [2] 4a d0 [2] 64 f2 [2] 70 e9 [2] 7f f3 [2] 61 ee [2] 63 ef [2] 78 e9 [2] 64 ee [2] 78 c1 }

  condition:
    any of them
}