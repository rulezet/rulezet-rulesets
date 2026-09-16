rule TTP_XOR_QUAD_CurrentVersionRun_de17 {
  strings:
    $key_de17 = { 8d 78 [2] a9 76 [2] 82 5a [2] ac 78 [2] b8 63 [2] b7 79 [2] a9 64 [2] ab 65 [2] b0 63 [2] ac 64 [2] b0 4b }

  condition:
    any of them
}