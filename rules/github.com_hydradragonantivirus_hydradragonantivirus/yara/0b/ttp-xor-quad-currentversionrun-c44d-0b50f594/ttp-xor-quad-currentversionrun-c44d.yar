rule TTP_XOR_QUAD_CurrentVersionRun_c44d {
  strings:
    $key_c44d = { 97 22 [2] b3 2c [2] 98 00 [2] b6 22 [2] a2 39 [2] ad 23 [2] b3 3e [2] b1 3f [2] aa 39 [2] b6 3e [2] aa 11 }

  condition:
    any of them
}