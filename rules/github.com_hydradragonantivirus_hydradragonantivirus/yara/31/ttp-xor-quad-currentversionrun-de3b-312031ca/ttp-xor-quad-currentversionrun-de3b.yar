rule TTP_XOR_QUAD_CurrentVersionRun_de3b {
  strings:
    $key_de3b = { 8d 54 [2] a9 5a [2] 82 76 [2] ac 54 [2] b8 4f [2] b7 55 [2] a9 48 [2] ab 49 [2] b0 4f [2] ac 48 [2] b0 67 }

  condition:
    any of them
}