rule TTP_XOR_QUAD_CurrentVersionRun_dc5f {
  strings:
    $key_dc5f = { 8f 30 [2] ab 3e [2] 80 12 [2] ae 30 [2] ba 2b [2] b5 31 [2] ab 2c [2] a9 2d [2] b2 2b [2] ae 2c [2] b2 03 }

  condition:
    any of them
}