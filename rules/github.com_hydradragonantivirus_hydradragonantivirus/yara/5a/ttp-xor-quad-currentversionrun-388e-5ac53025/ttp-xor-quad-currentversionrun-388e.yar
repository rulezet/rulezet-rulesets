rule TTP_XOR_QUAD_CurrentVersionRun_388e {
  strings:
    $key_388e = { 6b e1 [2] 4f ef [2] 64 c3 [2] 4a e1 [2] 5e fa [2] 51 e0 [2] 4f fd [2] 4d fc [2] 56 fa [2] 4a fd [2] 56 d2 }

  condition:
    any of them
}