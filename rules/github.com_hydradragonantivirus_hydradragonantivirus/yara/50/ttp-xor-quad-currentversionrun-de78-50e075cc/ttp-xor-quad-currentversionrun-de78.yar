rule TTP_XOR_QUAD_CurrentVersionRun_de78 {
  strings:
    $key_de78 = { 8d 17 [2] a9 19 [2] 82 35 [2] ac 17 [2] b8 0c [2] b7 16 [2] a9 0b [2] ab 0a [2] b0 0c [2] ac 0b [2] b0 24 }

  condition:
    any of them
}