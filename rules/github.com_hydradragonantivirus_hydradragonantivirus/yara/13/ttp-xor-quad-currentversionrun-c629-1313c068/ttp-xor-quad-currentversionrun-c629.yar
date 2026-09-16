rule TTP_XOR_QUAD_CurrentVersionRun_c629 {
  strings:
    $key_c629 = { 95 46 [2] b1 48 [2] 9a 64 [2] b4 46 [2] a0 5d [2] af 47 [2] b1 5a [2] b3 5b [2] a8 5d [2] b4 5a [2] a8 75 }

  condition:
    any of them
}