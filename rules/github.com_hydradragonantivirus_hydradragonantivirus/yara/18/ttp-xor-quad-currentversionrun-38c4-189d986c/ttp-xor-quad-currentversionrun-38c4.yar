rule TTP_XOR_QUAD_CurrentVersionRun_38c4 {
  strings:
    $key_38c4 = { 6b ab [2] 4f a5 [2] 64 89 [2] 4a ab [2] 5e b0 [2] 51 aa [2] 4f b7 [2] 4d b6 [2] 56 b0 [2] 4a b7 [2] 56 98 }

  condition:
    any of them
}