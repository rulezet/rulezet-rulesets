rule TTP_XOR_QUAD_CurrentVersionRun_de7b {
  strings:
    $key_de7b = { 8d 14 [2] a9 1a [2] 82 36 [2] ac 14 [2] b8 0f [2] b7 15 [2] a9 08 [2] ab 09 [2] b0 0f [2] ac 08 [2] b0 27 }

  condition:
    any of them
}