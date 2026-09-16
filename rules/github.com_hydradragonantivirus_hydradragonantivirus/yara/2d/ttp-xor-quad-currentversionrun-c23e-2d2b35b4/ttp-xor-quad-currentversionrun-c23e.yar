rule TTP_XOR_QUAD_CurrentVersionRun_c23e {
  strings:
    $key_c23e = { 91 51 [2] b5 5f [2] 9e 73 [2] b0 51 [2] a4 4a [2] ab 50 [2] b5 4d [2] b7 4c [2] ac 4a [2] b0 4d [2] ac 62 }

  condition:
    any of them
}