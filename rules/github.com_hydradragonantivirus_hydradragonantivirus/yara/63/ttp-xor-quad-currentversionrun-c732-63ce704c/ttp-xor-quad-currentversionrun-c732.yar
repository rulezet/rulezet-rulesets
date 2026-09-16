rule TTP_XOR_QUAD_CurrentVersionRun_c732 {
  strings:
    $key_c732 = { 94 5d [2] b0 53 [2] 9b 7f [2] b5 5d [2] a1 46 [2] ae 5c [2] b0 41 [2] b2 40 [2] a9 46 [2] b5 41 [2] a9 6e }

  condition:
    any of them
}