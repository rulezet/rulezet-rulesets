rule TTP_XOR_QUAD_CurrentVersionRun_289d {
  strings:
    $key_289d = { 7b f2 [2] 5f fc [2] 74 d0 [2] 5a f2 [2] 4e e9 [2] 41 f3 [2] 5f ee [2] 5d ef [2] 46 e9 [2] 5a ee [2] 46 c1 }

  condition:
    any of them
}