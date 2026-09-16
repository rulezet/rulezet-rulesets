rule TTP_XOR_QUAD_CurrentVersionRun_e9d1 {
  strings:
    $key_e9d1 = { ba be [2] 9e b0 [2] b5 9c [2] 9b be [2] 8f a5 [2] 80 bf [2] 9e a2 [2] 9c a3 [2] 87 a5 [2] 9b a2 [2] 87 8d }

  condition:
    any of them
}