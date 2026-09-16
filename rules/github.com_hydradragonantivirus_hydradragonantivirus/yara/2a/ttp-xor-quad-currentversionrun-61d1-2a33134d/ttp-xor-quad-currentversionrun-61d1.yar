rule TTP_XOR_QUAD_CurrentVersionRun_61d1 {
  strings:
    $key_61d1 = { 32 be [2] 16 b0 [2] 3d 9c [2] 13 be [2] 07 a5 [2] 08 bf [2] 16 a2 [2] 14 a3 [2] 0f a5 [2] 13 a2 [2] 0f 8d }

  condition:
    any of them
}