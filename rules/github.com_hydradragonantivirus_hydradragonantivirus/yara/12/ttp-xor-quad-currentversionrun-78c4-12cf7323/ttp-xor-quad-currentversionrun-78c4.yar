rule TTP_XOR_QUAD_CurrentVersionRun_78c4 {
  strings:
    $key_78c4 = { 2b ab [2] 0f a5 [2] 24 89 [2] 0a ab [2] 1e b0 [2] 11 aa [2] 0f b7 [2] 0d b6 [2] 16 b0 [2] 0a b7 [2] 16 98 }

  condition:
    any of them
}