rule TTP_XOR_QUAD_CurrentVersionRun_c27b {
  strings:
    $key_c27b = { 91 14 [2] b5 1a [2] 9e 36 [2] b0 14 [2] a4 0f [2] ab 15 [2] b5 08 [2] b7 09 [2] ac 0f [2] b0 08 [2] ac 27 }

  condition:
    any of them
}