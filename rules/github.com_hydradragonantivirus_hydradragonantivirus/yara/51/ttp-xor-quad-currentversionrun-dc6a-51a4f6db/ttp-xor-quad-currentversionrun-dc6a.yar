rule TTP_XOR_QUAD_CurrentVersionRun_dc6a {
  strings:
    $key_dc6a = { 8f 05 [2] ab 0b [2] 80 27 [2] ae 05 [2] ba 1e [2] b5 04 [2] ab 19 [2] a9 18 [2] b2 1e [2] ae 19 [2] b2 36 }

  condition:
    any of them
}