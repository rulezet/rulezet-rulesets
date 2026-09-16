rule TTP_XOR_QUAD_CurrentVersionRun_c01e {
  strings:
    $key_c01e = { 93 71 [2] b7 7f [2] 9c 53 [2] b2 71 [2] a6 6a [2] a9 70 [2] b7 6d [2] b5 6c [2] ae 6a [2] b2 6d [2] ae 42 }

  condition:
    any of them
}