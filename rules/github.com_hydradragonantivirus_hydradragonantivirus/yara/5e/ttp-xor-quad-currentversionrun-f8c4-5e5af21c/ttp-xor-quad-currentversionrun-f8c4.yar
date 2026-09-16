rule TTP_XOR_QUAD_CurrentVersionRun_f8c4 {
  strings:
    $key_f8c4 = { ab ab [2] 8f a5 [2] a4 89 [2] 8a ab [2] 9e b0 [2] 91 aa [2] 8f b7 [2] 8d b6 [2] 96 b0 [2] 8a b7 [2] 96 98 }

  condition:
    any of them
}