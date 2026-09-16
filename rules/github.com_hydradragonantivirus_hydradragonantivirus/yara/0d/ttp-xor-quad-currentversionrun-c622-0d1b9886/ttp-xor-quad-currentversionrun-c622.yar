rule TTP_XOR_QUAD_CurrentVersionRun_c622 {
  strings:
    $key_c622 = { 95 4d [2] b1 43 [2] 9a 6f [2] b4 4d [2] a0 56 [2] af 4c [2] b1 51 [2] b3 50 [2] a8 56 [2] b4 51 [2] a8 7e }

  condition:
    any of them
}