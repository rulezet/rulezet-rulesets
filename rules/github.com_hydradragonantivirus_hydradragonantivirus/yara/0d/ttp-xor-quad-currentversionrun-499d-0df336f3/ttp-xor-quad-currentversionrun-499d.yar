rule TTP_XOR_QUAD_CurrentVersionRun_499d {
  strings:
    $key_499d = { 1a f2 [2] 3e fc [2] 15 d0 [2] 3b f2 [2] 2f e9 [2] 20 f3 [2] 3e ee [2] 3c ef [2] 27 e9 [2] 3b ee [2] 27 c1 }

  condition:
    any of them
}