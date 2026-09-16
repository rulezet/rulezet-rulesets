rule TTP_XOR_QUAD_CurrentVersionRun_62c9 {
  strings:
    $key_62c9 = { 31 a6 [2] 15 a8 [2] 3e 84 [2] 10 a6 [2] 04 bd [2] 0b a7 [2] 15 ba [2] 17 bb [2] 0c bd [2] 10 ba [2] 0c 95 }

  condition:
    any of them
}