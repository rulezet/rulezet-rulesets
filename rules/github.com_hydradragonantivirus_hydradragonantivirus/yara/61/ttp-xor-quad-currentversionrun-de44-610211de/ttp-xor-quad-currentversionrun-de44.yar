rule TTP_XOR_QUAD_CurrentVersionRun_de44 {
  strings:
    $key_de44 = { 8d 2b [2] a9 25 [2] 82 09 [2] ac 2b [2] b8 30 [2] b7 2a [2] a9 37 [2] ab 36 [2] b0 30 [2] ac 37 [2] b0 18 }

  condition:
    any of them
}