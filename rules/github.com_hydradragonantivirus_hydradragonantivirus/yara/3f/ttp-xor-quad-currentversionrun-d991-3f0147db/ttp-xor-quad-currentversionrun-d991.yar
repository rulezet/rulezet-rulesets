rule TTP_XOR_QUAD_CurrentVersionRun_d991 {
  strings:
    $key_d991 = { 8a fe [2] ae f0 [2] 85 dc [2] ab fe [2] bf e5 [2] b0 ff [2] ae e2 [2] ac e3 [2] b7 e5 [2] ab e2 [2] b7 cd }

  condition:
    any of them
}