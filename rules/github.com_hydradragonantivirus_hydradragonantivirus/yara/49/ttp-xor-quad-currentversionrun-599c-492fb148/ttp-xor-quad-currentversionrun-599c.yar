rule TTP_XOR_QUAD_CurrentVersionRun_599c {
  strings:
    $key_599c = { 0a f3 [2] 2e fd [2] 05 d1 [2] 2b f3 [2] 3f e8 [2] 30 f2 [2] 2e ef [2] 2c ee [2] 37 e8 [2] 2b ef [2] 37 c0 }

  condition:
    any of them
}