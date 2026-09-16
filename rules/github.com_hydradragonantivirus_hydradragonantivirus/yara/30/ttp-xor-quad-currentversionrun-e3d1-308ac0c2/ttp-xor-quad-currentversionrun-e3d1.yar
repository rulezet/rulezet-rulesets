rule TTP_XOR_QUAD_CurrentVersionRun_e3d1 {
  strings:
    $key_e3d1 = { b0 be [2] 94 b0 [2] bf 9c [2] 91 be [2] 85 a5 [2] 8a bf [2] 94 a2 [2] 96 a3 [2] 8d a5 [2] 91 a2 [2] 8d 8d }

  condition:
    any of them
}