rule TTP_XOR_QUAD_CurrentVersionRun_c11d {
  strings:
    $key_c11d = { 92 72 [2] b6 7c [2] 9d 50 [2] b3 72 [2] a7 69 [2] a8 73 [2] b6 6e [2] b4 6f [2] af 69 [2] b3 6e [2] af 41 }

  condition:
    any of them
}