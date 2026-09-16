rule TTP_XOR_QUAD_CurrentVersionRun_c33f {
  strings:
    $key_c33f = { 90 50 [2] b4 5e [2] 9f 72 [2] b1 50 [2] a5 4b [2] aa 51 [2] b4 4c [2] b6 4d [2] ad 4b [2] b1 4c [2] ad 63 }

  condition:
    any of them
}