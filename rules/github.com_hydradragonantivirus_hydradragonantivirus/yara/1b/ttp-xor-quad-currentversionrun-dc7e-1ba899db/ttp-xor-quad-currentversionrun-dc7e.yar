rule TTP_XOR_QUAD_CurrentVersionRun_dc7e {
  strings:
    $key_dc7e = { 8f 11 [2] ab 1f [2] 80 33 [2] ae 11 [2] ba 0a [2] b5 10 [2] ab 0d [2] a9 0c [2] b2 0a [2] ae 0d [2] b2 22 }

  condition:
    any of them
}