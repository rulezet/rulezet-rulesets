rule TTP_XOR_QUAD_CurrentVersionRun_c610 {
  strings:
    $key_c610 = { 95 7f [2] b1 71 [2] 9a 5d [2] b4 7f [2] a0 64 [2] af 7e [2] b1 63 [2] b3 62 [2] a8 64 [2] b4 63 [2] a8 4c }

  condition:
    any of them
}