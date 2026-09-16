rule TTP_XOR_QUAD_CurrentVersionRun_e4d9 {
  strings:
    $key_e4d9 = { b7 b6 [2] 93 b8 [2] b8 94 [2] 96 b6 [2] 82 ad [2] 8d b7 [2] 93 aa [2] 91 ab [2] 8a ad [2] 96 aa [2] 8a 85 }

  condition:
    any of them
}