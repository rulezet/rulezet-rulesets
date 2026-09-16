rule TTP_XOR_QUAD_CurrentVersionRun_c51e {
  strings:
    $key_c51e = { 96 71 [2] b2 7f [2] 99 53 [2] b7 71 [2] a3 6a [2] ac 70 [2] b2 6d [2] b0 6c [2] ab 6a [2] b7 6d [2] ab 42 }

  condition:
    any of them
}