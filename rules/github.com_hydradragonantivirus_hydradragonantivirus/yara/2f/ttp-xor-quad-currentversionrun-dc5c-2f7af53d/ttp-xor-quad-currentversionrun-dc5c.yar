rule TTP_XOR_QUAD_CurrentVersionRun_dc5c {
  strings:
    $key_dc5c = { 8f 33 [2] ab 3d [2] 80 11 [2] ae 33 [2] ba 28 [2] b5 32 [2] ab 2f [2] a9 2e [2] b2 28 [2] ae 2f [2] b2 00 }

  condition:
    any of them
}