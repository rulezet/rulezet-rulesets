rule TTP_XOR_QUAD_CurrentVersionRun_de0b {
  strings:
    $key_de0b = { 8d 64 [2] a9 6a [2] 82 46 [2] ac 64 [2] b8 7f [2] b7 65 [2] a9 78 [2] ab 79 [2] b0 7f [2] ac 78 [2] b0 57 }

  condition:
    any of them
}