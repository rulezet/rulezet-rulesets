rule TTP_XOR_QUAD_CurrentVersionRun_c17f {
  strings:
    $key_c17f = { 92 10 [2] b6 1e [2] 9d 32 [2] b3 10 [2] a7 0b [2] a8 11 [2] b6 0c [2] b4 0d [2] af 0b [2] b3 0c [2] af 23 }

  condition:
    any of them
}