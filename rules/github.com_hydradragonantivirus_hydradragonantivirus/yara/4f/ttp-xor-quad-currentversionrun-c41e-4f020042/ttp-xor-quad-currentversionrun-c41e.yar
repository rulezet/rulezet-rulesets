rule TTP_XOR_QUAD_CurrentVersionRun_c41e {
  strings:
    $key_c41e = { 97 71 [2] b3 7f [2] 98 53 [2] b6 71 [2] a2 6a [2] ad 70 [2] b3 6d [2] b1 6c [2] aa 6a [2] b6 6d [2] aa 42 }

  condition:
    any of them
}