rule TTP_XOR_QUAD_CurrentVersionRun_e5d9 {
  strings:
    $key_e5d9 = { b6 b6 [2] 92 b8 [2] b9 94 [2] 97 b6 [2] 83 ad [2] 8c b7 [2] 92 aa [2] 90 ab [2] 8b ad [2] 97 aa [2] 8b 85 }

  condition:
    any of them
}