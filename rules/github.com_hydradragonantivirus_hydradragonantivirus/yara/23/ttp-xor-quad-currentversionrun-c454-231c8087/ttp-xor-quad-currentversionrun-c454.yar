rule TTP_XOR_QUAD_CurrentVersionRun_c454 {
  strings:
    $key_c454 = { 97 3b [2] b3 35 [2] 98 19 [2] b6 3b [2] a2 20 [2] ad 3a [2] b3 27 [2] b1 26 [2] aa 20 [2] b6 27 [2] aa 08 }

  condition:
    any of them
}