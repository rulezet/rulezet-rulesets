rule TTP_XOR_QUAD_CurrentVersionRun_de6b {
  strings:
    $key_de6b = { 8d 04 [2] a9 0a [2] 82 26 [2] ac 04 [2] b8 1f [2] b7 05 [2] a9 18 [2] ab 19 [2] b0 1f [2] ac 18 [2] b0 37 }

  condition:
    any of them
}