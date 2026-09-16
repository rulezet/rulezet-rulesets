rule TTP_XOR_QUAD_CurrentVersionRun_dc4a {
  strings:
    $key_dc4a = { 8f 25 [2] ab 2b [2] 80 07 [2] ae 25 [2] ba 3e [2] b5 24 [2] ab 39 [2] a9 38 [2] b2 3e [2] ae 39 [2] b2 16 }

  condition:
    any of them
}