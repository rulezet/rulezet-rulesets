rule TTP_XOR_QUAD_CurrentVersionRun_c111 {
  strings:
    $key_c111 = { 92 7e [2] b6 70 [2] 9d 5c [2] b3 7e [2] a7 65 [2] a8 7f [2] b6 62 [2] b4 63 [2] af 65 [2] b3 62 [2] af 4d }

  condition:
    any of them
}