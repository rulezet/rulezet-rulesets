rule TTP_XOR_QUAD_CurrentVersionRun_c42c {
  strings:
    $key_c42c = { 97 43 [2] b3 4d [2] 98 61 [2] b6 43 [2] a2 58 [2] ad 42 [2] b3 5f [2] b1 5e [2] aa 58 [2] b6 5f [2] aa 70 }

  condition:
    any of them
}