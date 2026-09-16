rule TTP_XOR_QUAD_CurrentVersionRun_ff87 {
  strings:
    $key_ff87 = { ac e8 [2] 88 e6 [2] a3 ca [2] 8d e8 [2] 99 f3 [2] 96 e9 [2] 88 f4 [2] 8a f5 [2] 91 f3 [2] 8d f4 [2] 91 db }

  condition:
    any of them
}