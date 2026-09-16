rule TTP_XOR_QUAD_CurrentVersionRun_c1fc {
  strings:
    $key_c1fc = { 92 93 [2] b6 9d [2] 9d b1 [2] b3 93 [2] a7 88 [2] a8 92 [2] b6 8f [2] b4 8e [2] af 88 [2] b3 8f [2] af a0 }

  condition:
    any of them
}