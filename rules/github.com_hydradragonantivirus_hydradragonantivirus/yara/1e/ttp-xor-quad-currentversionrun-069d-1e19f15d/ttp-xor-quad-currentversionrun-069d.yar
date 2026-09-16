rule TTP_XOR_QUAD_CurrentVersionRun_069d {
  strings:
    $key_069d = { 55 f2 [2] 71 fc [2] 5a d0 [2] 74 f2 [2] 60 e9 [2] 6f f3 [2] 71 ee [2] 73 ef [2] 68 e9 [2] 74 ee [2] 68 c1 }

  condition:
    any of them
}