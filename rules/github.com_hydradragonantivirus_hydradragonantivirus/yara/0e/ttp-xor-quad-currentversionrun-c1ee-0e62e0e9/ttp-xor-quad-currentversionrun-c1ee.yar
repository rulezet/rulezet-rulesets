rule TTP_XOR_QUAD_CurrentVersionRun_c1ee {
  strings:
    $key_c1ee = { 92 81 [2] b6 8f [2] 9d a3 [2] b3 81 [2] a7 9a [2] a8 80 [2] b6 9d [2] b4 9c [2] af 9a [2] b3 9d [2] af b2 }

  condition:
    any of them
}