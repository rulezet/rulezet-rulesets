rule TTP_XOR_QUAD_CurrentVersionRun_f3d8 {
  strings:
    $key_f3d8 = { a0 b7 [2] 84 b9 [2] af 95 [2] 81 b7 [2] 95 ac [2] 9a b6 [2] 84 ab [2] 86 aa [2] 9d ac [2] 81 ab [2] 9d 84 }

  condition:
    any of them
}