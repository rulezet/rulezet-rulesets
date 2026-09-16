rule TTP_XOR_QUAD_CurrentVersionRun_c3fe {
  strings:
    $key_c3fe = { 90 91 [2] b4 9f [2] 9f b3 [2] b1 91 [2] a5 8a [2] aa 90 [2] b4 8d [2] b6 8c [2] ad 8a [2] b1 8d [2] ad a2 }

  condition:
    any of them
}