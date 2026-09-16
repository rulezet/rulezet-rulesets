rule TTP_XOR_QUAD_CurrentVersionRun_189d {
  strings:
    $key_189d = { 4b f2 [2] 6f fc [2] 44 d0 [2] 6a f2 [2] 7e e9 [2] 71 f3 [2] 6f ee [2] 6d ef [2] 76 e9 [2] 6a ee [2] 76 c1 }

  condition:
    any of them
}