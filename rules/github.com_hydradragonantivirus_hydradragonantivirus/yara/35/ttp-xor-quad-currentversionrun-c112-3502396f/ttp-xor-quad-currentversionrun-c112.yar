rule TTP_XOR_QUAD_CurrentVersionRun_c112 {
  strings:
    $key_c112 = { 92 7d [2] b6 73 [2] 9d 5f [2] b3 7d [2] a7 66 [2] a8 7c [2] b6 61 [2] b4 60 [2] af 66 [2] b3 61 [2] af 4e }

  condition:
    any of them
}