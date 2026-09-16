rule TTP_XOR_QUAD_CurrentVersionRun_399d {
  strings:
    $key_399d = { 6a f2 [2] 4e fc [2] 65 d0 [2] 4b f2 [2] 5f e9 [2] 50 f3 [2] 4e ee [2] 4c ef [2] 57 e9 [2] 4b ee [2] 57 c1 }

  condition:
    any of them
}