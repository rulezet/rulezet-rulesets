rule TTP_XOR_QUAD_CurrentVersionRun_c130 {
  strings:
    $key_c130 = { 92 5f [2] b6 51 [2] 9d 7d [2] b3 5f [2] a7 44 [2] a8 5e [2] b6 43 [2] b4 42 [2] af 44 [2] b3 43 [2] af 6c }

  condition:
    any of them
}