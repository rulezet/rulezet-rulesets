rule TTP_XOR_QUAD_CurrentVersionRun_de1b {
  strings:
    $key_de1b = { 8d 74 [2] a9 7a [2] 82 56 [2] ac 74 [2] b8 6f [2] b7 75 [2] a9 68 [2] ab 69 [2] b0 6f [2] ac 68 [2] b0 47 }

  condition:
    any of them
}