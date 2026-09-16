rule TTP_XOR_QUAD_CurrentVersionRun_c41c {
  strings:
    $key_c41c = { 97 73 [2] b3 7d [2] 98 51 [2] b6 73 [2] a2 68 [2] ad 72 [2] b3 6f [2] b1 6e [2] aa 68 [2] b6 6f [2] aa 40 }

  condition:
    any of them
}