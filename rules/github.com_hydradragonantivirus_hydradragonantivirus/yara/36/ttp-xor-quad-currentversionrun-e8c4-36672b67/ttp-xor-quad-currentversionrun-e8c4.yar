rule TTP_XOR_QUAD_CurrentVersionRun_e8c4 {
  strings:
    $key_e8c4 = { bb ab [2] 9f a5 [2] b4 89 [2] 9a ab [2] 8e b0 [2] 81 aa [2] 9f b7 [2] 9d b6 [2] 86 b0 [2] 9a b7 [2] 86 98 }

  condition:
    any of them
}