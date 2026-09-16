rule TTP_XOR_QUAD_CurrentVersionRun_499c {
  strings:
    $key_499c = { 1a f3 [2] 3e fd [2] 15 d1 [2] 3b f3 [2] 2f e8 [2] 20 f2 [2] 3e ef [2] 3c ee [2] 27 e8 [2] 3b ef [2] 27 c0 }

  condition:
    any of them
}