rule TTP_XOR_QUAD_CurrentVersionRun_dc6e {
  strings:
    $key_dc6e = { 8f 01 [2] ab 0f [2] 80 23 [2] ae 01 [2] ba 1a [2] b5 00 [2] ab 1d [2] a9 1c [2] b2 1a [2] ae 1d [2] b2 32 }

  condition:
    any of them
}