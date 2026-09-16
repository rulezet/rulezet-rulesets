rule TTP_XOR_QUAD_CurrentVersionRun_c53e {
  strings:
    $key_c53e = { 96 51 [2] b2 5f [2] 99 73 [2] b7 51 [2] a3 4a [2] ac 50 [2] b2 4d [2] b0 4c [2] ab 4a [2] b7 4d [2] ab 62 }

  condition:
    any of them
}