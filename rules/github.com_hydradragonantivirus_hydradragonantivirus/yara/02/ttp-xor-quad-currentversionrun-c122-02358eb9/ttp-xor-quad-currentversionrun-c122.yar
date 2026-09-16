rule TTP_XOR_QUAD_CurrentVersionRun_c122 {
  strings:
    $key_c122 = { 92 4d [2] b6 43 [2] 9d 6f [2] b3 4d [2] a7 56 [2] a8 4c [2] b6 51 [2] b4 50 [2] af 56 [2] b3 51 [2] af 7e }

  condition:
    any of them
}