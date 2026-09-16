rule TTP_XOR_QUAD_CurrentVersionRun_eec4 {
  strings:
    $key_eec4 = { bd ab [2] 99 a5 [2] b2 89 [2] 9c ab [2] 88 b0 [2] 87 aa [2] 99 b7 [2] 9b b6 [2] 80 b0 [2] 9c b7 [2] 80 98 }

  condition:
    any of them
}