rule TTP_XOR_QUAD_CurrentVersionRun_c57e {
  strings:
    $key_c57e = { 96 11 [2] b2 1f [2] 99 33 [2] b7 11 [2] a3 0a [2] ac 10 [2] b2 0d [2] b0 0c [2] ab 0a [2] b7 0d [2] ab 22 }

  condition:
    any of them
}