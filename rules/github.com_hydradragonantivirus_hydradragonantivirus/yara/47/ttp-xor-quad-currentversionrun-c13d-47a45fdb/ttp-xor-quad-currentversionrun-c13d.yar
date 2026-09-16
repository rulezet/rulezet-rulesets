rule TTP_XOR_QUAD_CurrentVersionRun_c13d {
  strings:
    $key_c13d = { 92 52 [2] b6 5c [2] 9d 70 [2] b3 52 [2] a7 49 [2] a8 53 [2] b6 4e [2] b4 4f [2] af 49 [2] b3 4e [2] af 61 }

  condition:
    any of them
}