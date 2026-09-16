rule TTP_XOR_QUAD_CurrentVersionRun_298e {
  strings:
    $key_298e = { 7a e1 [2] 5e ef [2] 75 c3 [2] 5b e1 [2] 4f fa [2] 40 e0 [2] 5e fd [2] 5c fc [2] 47 fa [2] 5b fd [2] 47 d2 }

  condition:
    any of them
}