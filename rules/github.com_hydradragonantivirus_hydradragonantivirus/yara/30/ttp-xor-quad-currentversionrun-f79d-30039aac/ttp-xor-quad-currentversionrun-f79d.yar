rule TTP_XOR_QUAD_CurrentVersionRun_f79d {
  strings:
    $key_f79d = { a4 f2 [2] 80 fc [2] ab d0 [2] 85 f2 [2] 91 e9 [2] 9e f3 [2] 80 ee [2] 82 ef [2] 99 e9 [2] 85 ee [2] 99 c1 }

  condition:
    any of them
}