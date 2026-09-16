rule TTP_XOR_QUAD_CurrentVersionRun_de37 {
  strings:
    $key_de37 = { 8d 58 [2] a9 56 [2] 82 7a [2] ac 58 [2] b8 43 [2] b7 59 [2] a9 44 [2] ab 45 [2] b0 43 [2] ac 44 [2] b0 6b }

  condition:
    any of them
}