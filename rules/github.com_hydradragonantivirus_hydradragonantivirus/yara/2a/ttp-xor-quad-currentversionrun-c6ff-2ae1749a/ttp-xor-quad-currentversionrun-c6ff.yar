rule TTP_XOR_QUAD_CurrentVersionRun_c6ff {
  strings:
    $key_c6ff = { 95 90 [2] b1 9e [2] 9a b2 [2] b4 90 [2] a0 8b [2] af 91 [2] b1 8c [2] b3 8d [2] a8 8b [2] b4 8c [2] a8 a3 }

  condition:
    any of them
}