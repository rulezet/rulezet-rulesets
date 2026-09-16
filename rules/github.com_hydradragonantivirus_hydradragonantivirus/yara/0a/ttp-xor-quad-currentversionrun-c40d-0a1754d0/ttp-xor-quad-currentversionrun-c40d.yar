rule TTP_XOR_QUAD_CurrentVersionRun_c40d {
  strings:
    $key_c40d = { 97 62 [2] b3 6c [2] 98 40 [2] b6 62 [2] a2 79 [2] ad 63 [2] b3 7e [2] b1 7f [2] aa 79 [2] b6 7e [2] aa 51 }

  condition:
    any of them
}