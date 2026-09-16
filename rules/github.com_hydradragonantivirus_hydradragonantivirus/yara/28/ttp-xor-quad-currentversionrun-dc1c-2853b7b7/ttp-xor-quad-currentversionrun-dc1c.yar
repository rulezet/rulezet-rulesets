rule TTP_XOR_QUAD_CurrentVersionRun_dc1c {
  strings:
    $key_dc1c = { 8f 73 [2] ab 7d [2] 80 51 [2] ae 73 [2] ba 68 [2] b5 72 [2] ab 6f [2] a9 6e [2] b2 68 [2] ae 6f [2] b2 40 }

  condition:
    any of them
}