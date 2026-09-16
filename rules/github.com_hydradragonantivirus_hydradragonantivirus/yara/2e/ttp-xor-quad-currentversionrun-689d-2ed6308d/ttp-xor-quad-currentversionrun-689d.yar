rule TTP_XOR_QUAD_CurrentVersionRun_689d {
  strings:
    $key_689d = { 3b f2 [2] 1f fc [2] 34 d0 [2] 1a f2 [2] 0e e9 [2] 01 f3 [2] 1f ee [2] 1d ef [2] 06 e9 [2] 1a ee [2] 06 c1 }

  condition:
    any of them
}