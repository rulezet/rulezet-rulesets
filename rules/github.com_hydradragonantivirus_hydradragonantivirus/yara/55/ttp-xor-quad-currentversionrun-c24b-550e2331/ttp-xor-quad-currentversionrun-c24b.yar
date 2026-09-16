rule TTP_XOR_QUAD_CurrentVersionRun_c24b {
  strings:
    $key_c24b = { 91 24 [2] b5 2a [2] 9e 06 [2] b0 24 [2] a4 3f [2] ab 25 [2] b5 38 [2] b7 39 [2] ac 3f [2] b0 38 [2] ac 17 }

  condition:
    any of them
}