rule TTP_XOR_QUAD_CurrentVersionRun_f89c {
  strings:
    $key_f89c = { ab f3 [2] 8f fd [2] a4 d1 [2] 8a f3 [2] 9e e8 [2] 91 f2 [2] 8f ef [2] 8d ee [2] 96 e8 [2] 8a ef [2] 96 c0 }

  condition:
    any of them
}