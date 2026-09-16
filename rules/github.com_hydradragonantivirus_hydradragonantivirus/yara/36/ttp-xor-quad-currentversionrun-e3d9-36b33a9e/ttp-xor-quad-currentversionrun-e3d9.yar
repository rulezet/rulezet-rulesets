rule TTP_XOR_QUAD_CurrentVersionRun_e3d9 {
  strings:
    $key_e3d9 = { b0 b6 [2] 94 b8 [2] bf 94 [2] 91 b6 [2] 85 ad [2] 8a b7 [2] 94 aa [2] 96 ab [2] 8d ad [2] 91 aa [2] 8d 85 }

  condition:
    any of them
}