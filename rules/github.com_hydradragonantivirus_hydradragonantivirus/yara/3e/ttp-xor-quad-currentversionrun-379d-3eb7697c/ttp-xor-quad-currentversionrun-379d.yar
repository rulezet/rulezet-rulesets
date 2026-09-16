rule TTP_XOR_QUAD_CurrentVersionRun_379d {
  strings:
    $key_379d = { 64 f2 [2] 40 fc [2] 6b d0 [2] 45 f2 [2] 51 e9 [2] 5e f3 [2] 40 ee [2] 42 ef [2] 59 e9 [2] 45 ee [2] 59 c1 }

  condition:
    any of them
}