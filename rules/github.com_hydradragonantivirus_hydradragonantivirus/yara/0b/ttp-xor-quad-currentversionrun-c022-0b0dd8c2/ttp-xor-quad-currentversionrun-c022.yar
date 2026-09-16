rule TTP_XOR_QUAD_CurrentVersionRun_c022 {
  strings:
    $key_c022 = { 93 4d [2] b7 43 [2] 9c 6f [2] b2 4d [2] a6 56 [2] a9 4c [2] b7 51 [2] b5 50 [2] ae 56 [2] b2 51 [2] ae 7e }

  condition:
    any of them
}