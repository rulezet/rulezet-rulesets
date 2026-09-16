rule TTP_XOR_QUAD_CurrentVersionRun_ef87 {
  strings:
    $key_ef87 = { bc e8 [2] 98 e6 [2] b3 ca [2] 9d e8 [2] 89 f3 [2] 86 e9 [2] 98 f4 [2] 9a f5 [2] 81 f3 [2] 9d f4 [2] 81 db }

  condition:
    any of them
}