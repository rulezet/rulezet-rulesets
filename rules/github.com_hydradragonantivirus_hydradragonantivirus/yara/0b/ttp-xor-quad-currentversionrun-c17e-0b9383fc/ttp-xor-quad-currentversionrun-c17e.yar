rule TTP_XOR_QUAD_CurrentVersionRun_c17e {
  strings:
    $key_c17e = { 92 11 [2] b6 1f [2] 9d 33 [2] b3 11 [2] a7 0a [2] a8 10 [2] b6 0d [2] b4 0c [2] af 0a [2] b3 0d [2] af 22 }

  condition:
    any of them
}