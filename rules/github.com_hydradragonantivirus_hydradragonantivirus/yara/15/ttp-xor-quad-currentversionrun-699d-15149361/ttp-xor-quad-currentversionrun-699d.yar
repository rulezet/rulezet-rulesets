rule TTP_XOR_QUAD_CurrentVersionRun_699d {
  strings:
    $key_699d = { 3a f2 [2] 1e fc [2] 35 d0 [2] 1b f2 [2] 0f e9 [2] 00 f3 [2] 1e ee [2] 1c ef [2] 07 e9 [2] 1b ee [2] 07 c1 }

  condition:
    any of them
}