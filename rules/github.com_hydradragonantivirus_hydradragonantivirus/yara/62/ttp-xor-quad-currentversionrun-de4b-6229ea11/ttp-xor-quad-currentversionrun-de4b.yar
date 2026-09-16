rule TTP_XOR_QUAD_CurrentVersionRun_de4b {
  strings:
    $key_de4b = { 8d 24 [2] a9 2a [2] 82 06 [2] ac 24 [2] b8 3f [2] b7 25 [2] a9 38 [2] ab 39 [2] b0 3f [2] ac 38 [2] b0 17 }

  condition:
    any of them
}