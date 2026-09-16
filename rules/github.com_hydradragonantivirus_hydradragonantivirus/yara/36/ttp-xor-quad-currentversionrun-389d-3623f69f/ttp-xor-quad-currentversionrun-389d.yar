rule TTP_XOR_QUAD_CurrentVersionRun_389d {
  strings:
    $key_389d = { 6b f2 [2] 4f fc [2] 64 d0 [2] 4a f2 [2] 5e e9 [2] 51 f3 [2] 4f ee [2] 4d ef [2] 56 e9 [2] 4a ee [2] 56 c1 }

  condition:
    any of them
}