rule TTP_XOR_QUAD_CurrentVersionRun_c60c {
  strings:
    $key_c60c = { 95 63 [2] b1 6d [2] 9a 41 [2] b4 63 [2] a0 78 [2] af 62 [2] b1 7f [2] b3 7e [2] a8 78 [2] b4 7f [2] a8 50 }

  condition:
    any of them
}