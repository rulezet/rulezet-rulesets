rule TTP_XOR_QUAD_CurrentVersionRun_589d {
  strings:
    $key_589d = { 0b f2 [2] 2f fc [2] 04 d0 [2] 2a f2 [2] 3e e9 [2] 31 f3 [2] 2f ee [2] 2d ef [2] 36 e9 [2] 2a ee [2] 36 c1 }

  condition:
    any of them
}