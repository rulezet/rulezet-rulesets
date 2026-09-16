rule TTP_XOR_QUAD_CurrentVersionRun_ff9d {
  strings:
    $key_ff9d = { ac f2 [2] 88 fc [2] a3 d0 [2] 8d f2 [2] 99 e9 [2] 96 f3 [2] 88 ee [2] 8a ef [2] 91 e9 [2] 8d ee [2] 91 c1 }

  condition:
    any of them
}