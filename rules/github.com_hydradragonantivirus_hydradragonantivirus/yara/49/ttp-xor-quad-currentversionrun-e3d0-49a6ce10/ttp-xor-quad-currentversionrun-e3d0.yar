rule TTP_XOR_QUAD_CurrentVersionRun_e3d0 {
  strings:
    $key_e3d0 = { b0 bf [2] 94 b1 [2] bf 9d [2] 91 bf [2] 85 a4 [2] 8a be [2] 94 a3 [2] 96 a2 [2] 8d a4 [2] 91 a3 [2] 8d 8c }

  condition:
    any of them
}