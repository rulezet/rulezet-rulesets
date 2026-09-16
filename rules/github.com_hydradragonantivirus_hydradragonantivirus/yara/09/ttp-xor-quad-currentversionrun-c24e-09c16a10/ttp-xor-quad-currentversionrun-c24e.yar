rule TTP_XOR_QUAD_CurrentVersionRun_c24e {
  strings:
    $key_c24e = { 91 21 [2] b5 2f [2] 9e 03 [2] b0 21 [2] a4 3a [2] ab 20 [2] b5 3d [2] b7 3c [2] ac 3a [2] b0 3d [2] ac 12 }

  condition:
    any of them
}