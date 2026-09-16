rule TTP_XOR_QUAD_CurrentVersionRun_c10e {
  strings:
    $key_c10e = { 92 61 [2] b6 6f [2] 9d 43 [2] b3 61 [2] a7 7a [2] a8 60 [2] b6 7d [2] b4 7c [2] af 7a [2] b3 7d [2] af 52 }

  condition:
    any of them
}