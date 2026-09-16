rule TTP_XOR_QUAD_CurrentVersionRun_799d {
  strings:
    $key_799d = { 2a f2 [2] 0e fc [2] 25 d0 [2] 0b f2 [2] 1f e9 [2] 10 f3 [2] 0e ee [2] 0c ef [2] 17 e9 [2] 0b ee [2] 17 c1 }

  condition:
    any of them
}