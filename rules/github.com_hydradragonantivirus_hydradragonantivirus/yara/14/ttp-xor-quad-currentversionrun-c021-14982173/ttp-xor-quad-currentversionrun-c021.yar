rule TTP_XOR_QUAD_CurrentVersionRun_c021 {
  strings:
    $key_c021 = { 93 4e [2] b7 40 [2] 9c 6c [2] b2 4e [2] a6 55 [2] a9 4f [2] b7 52 [2] b5 53 [2] ae 55 [2] b2 52 [2] ae 7d }

  condition:
    any of them
}