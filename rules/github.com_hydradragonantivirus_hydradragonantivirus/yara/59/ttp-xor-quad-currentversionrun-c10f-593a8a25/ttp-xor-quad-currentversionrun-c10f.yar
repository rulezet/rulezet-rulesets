rule TTP_XOR_QUAD_CurrentVersionRun_c10f {
  strings:
    $key_c10f = { 92 60 [2] b6 6e [2] 9d 42 [2] b3 60 [2] a7 7b [2] a8 61 [2] b6 7c [2] b4 7d [2] af 7b [2] b3 7c [2] af 53 }

  condition:
    any of them
}