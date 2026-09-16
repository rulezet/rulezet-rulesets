rule TTP_XOR_QUAD_CurrentVersionRun_ff80 {
  strings:
    $key_ff80 = { ac ef [2] 88 e1 [2] a3 cd [2] 8d ef [2] 99 f4 [2] 96 ee [2] 88 f3 [2] 8a f2 [2] 91 f4 [2] 8d f3 [2] 91 dc }

  condition:
    any of them
}