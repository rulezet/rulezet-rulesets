rule TTP_XOR_QUAD_CurrentVersionRun_61d0 {
  strings:
    $key_61d0 = { 32 bf [2] 16 b1 [2] 3d 9d [2] 13 bf [2] 07 a4 [2] 08 be [2] 16 a3 [2] 14 a2 [2] 0f a4 [2] 13 a3 [2] 0f 8c }

  condition:
    any of them
}