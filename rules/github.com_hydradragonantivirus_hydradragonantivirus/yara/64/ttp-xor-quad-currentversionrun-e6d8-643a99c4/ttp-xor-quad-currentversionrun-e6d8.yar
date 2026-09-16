rule TTP_XOR_QUAD_CurrentVersionRun_e6d8 {
  strings:
    $key_e6d8 = { b5 b7 [2] 91 b9 [2] ba 95 [2] 94 b7 [2] 80 ac [2] 8f b6 [2] 91 ab [2] 93 aa [2] 88 ac [2] 94 ab [2] 88 84 }

  condition:
    any of them
}