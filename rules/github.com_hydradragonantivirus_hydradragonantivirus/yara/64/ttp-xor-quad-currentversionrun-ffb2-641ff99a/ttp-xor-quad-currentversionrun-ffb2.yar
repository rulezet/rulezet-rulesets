rule TTP_XOR_QUAD_CurrentVersionRun_ffb2 {
  strings:
    $key_ffb2 = { ac dd [2] 88 d3 [2] a3 ff [2] 8d dd [2] 99 c6 [2] 96 dc [2] 88 c1 [2] 8a c0 [2] 91 c6 [2] 8d c1 [2] 91 ee }

  condition:
    any of them
}