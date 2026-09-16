rule TTP_XOR_QUAD_CurrentVersionRun_699c {
  strings:
    $key_699c = { 3a f3 [2] 1e fd [2] 35 d1 [2] 1b f3 [2] 0f e8 [2] 00 f2 [2] 1e ef [2] 1c ee [2] 07 e8 [2] 1b ef [2] 07 c0 }

  condition:
    any of them
}