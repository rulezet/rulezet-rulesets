rule TTP_XOR_QUAD_CurrentVersionRun_dc42 {
  strings:
    $key_dc42 = { 8f 2d [2] ab 23 [2] 80 0f [2] ae 2d [2] ba 36 [2] b5 2c [2] ab 31 [2] a9 30 [2] b2 36 [2] ae 31 [2] b2 1e }

  condition:
    any of them
}