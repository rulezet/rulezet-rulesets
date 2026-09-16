rule TTP_XOR_QUAD_CurrentVersionRun_e89c {
  strings:
    $key_e89c = { bb f3 [2] 9f fd [2] b4 d1 [2] 9a f3 [2] 8e e8 [2] 81 f2 [2] 9f ef [2] 9d ee [2] 86 e8 [2] 9a ef [2] 86 c0 }

  condition:
    any of them
}