rule TTP_XOR_QUAD_CurrentVersionRun_de09 {
  strings:
    $key_de09 = { 8d 66 [2] a9 68 [2] 82 44 [2] ac 66 [2] b8 7d [2] b7 67 [2] a9 7a [2] ab 7b [2] b0 7d [2] ac 7a [2] b0 55 }

  condition:
    any of them
}