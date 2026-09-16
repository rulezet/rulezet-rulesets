rule TTP_XOR_QUAD_CurrentVersionRun_e8d9 {
  strings:
    $key_e8d9 = { bb b6 [2] 9f b8 [2] b4 94 [2] 9a b6 [2] 8e ad [2] 81 b7 [2] 9f aa [2] 9d ab [2] 86 ad [2] 9a aa [2] 86 85 }

  condition:
    any of them
}