rule TTP_XOR_QUAD_CurrentVersionRun_dc7f {
  strings:
    $key_dc7f = { 8f 10 [2] ab 1e [2] 80 32 [2] ae 10 [2] ba 0b [2] b5 11 [2] ab 0c [2] a9 0d [2] b2 0b [2] ae 0c [2] b2 23 }

  condition:
    any of them
}