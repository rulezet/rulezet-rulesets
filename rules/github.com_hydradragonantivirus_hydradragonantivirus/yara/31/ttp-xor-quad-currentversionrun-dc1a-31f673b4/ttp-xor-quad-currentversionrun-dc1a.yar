rule TTP_XOR_QUAD_CurrentVersionRun_dc1a {
  strings:
    $key_dc1a = { 8f 75 [2] ab 7b [2] 80 57 [2] ae 75 [2] ba 6e [2] b5 74 [2] ab 69 [2] a9 68 [2] b2 6e [2] ae 69 [2] b2 46 }

  condition:
    any of them
}