rule TTP_XOR_QUAD_CurrentVersionRun_dc7d {
  strings:
    $key_dc7d = { 8f 12 [2] ab 1c [2] 80 30 [2] ae 12 [2] ba 09 [2] b5 13 [2] ab 0e [2] a9 0f [2] b2 09 [2] ae 0e [2] b2 21 }

  condition:
    any of them
}