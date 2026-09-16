rule TTP_XOR_QUAD_CurrentVersionRun_d996 {
  strings:
    $key_d996 = { 8a f9 [2] ae f7 [2] 85 db [2] ab f9 [2] bf e2 [2] b0 f8 [2] ae e5 [2] ac e4 [2] b7 e2 [2] ab e5 [2] b7 ca }

  condition:
    any of them
}