rule TTP_XOR_QUAD_CurrentVersionRun_769d {
  strings:
    $key_769d = { 25 f2 [2] 01 fc [2] 2a d0 [2] 04 f2 [2] 10 e9 [2] 1f f3 [2] 01 ee [2] 03 ef [2] 18 e9 [2] 04 ee [2] 18 c1 }

  condition:
    any of them
}