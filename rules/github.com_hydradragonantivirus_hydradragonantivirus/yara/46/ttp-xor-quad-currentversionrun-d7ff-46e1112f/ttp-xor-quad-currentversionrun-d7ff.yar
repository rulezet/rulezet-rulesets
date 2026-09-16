rule TTP_XOR_QUAD_CurrentVersionRun_d7ff {
  strings:
    $key_d7ff = { 84 90 [2] a0 9e [2] 8b b2 [2] a5 90 [2] b1 8b [2] be 91 [2] a0 8c [2] a2 8d [2] b9 8b [2] a5 8c [2] b9 a3 }

  condition:
    any of them
}