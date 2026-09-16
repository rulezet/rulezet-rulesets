rule TTP_XOR_QUAD_CurrentVersionRun_c46c {
  strings:
    $key_c46c = { 97 03 [2] b3 0d [2] 98 21 [2] b6 03 [2] a2 18 [2] ad 02 [2] b3 1f [2] b1 1e [2] aa 18 [2] b6 1f [2] aa 30 }

  condition:
    any of them
}