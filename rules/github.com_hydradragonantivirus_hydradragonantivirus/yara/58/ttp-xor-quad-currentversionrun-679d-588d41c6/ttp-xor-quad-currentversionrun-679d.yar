rule TTP_XOR_QUAD_CurrentVersionRun_679d {
  strings:
    $key_679d = { 34 f2 [2] 10 fc [2] 3b d0 [2] 15 f2 [2] 01 e9 [2] 0e f3 [2] 10 ee [2] 12 ef [2] 09 e9 [2] 15 ee [2] 09 c1 }

  condition:
    any of them
}