rule TTP_XOR_QUAD_CurrentVersionRun_e89d {
  strings:
    $key_e89d = { bb f2 [2] 9f fc [2] b4 d0 [2] 9a f2 [2] 8e e9 [2] 81 f3 [2] 9f ee [2] 9d ef [2] 86 e9 [2] 9a ee [2] 86 c1 }

  condition:
    any of them
}