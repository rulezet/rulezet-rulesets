rule TTP_XOR_QUAD_CurrentVersionRun_e8ca {
  strings:
    $key_e8ca = { bb a5 [2] 9f ab [2] b4 87 [2] 9a a5 [2] 8e be [2] 81 a4 [2] 9f b9 [2] 9d b8 [2] 86 be [2] 9a b9 [2] 86 96 }

  condition:
    any of them
}