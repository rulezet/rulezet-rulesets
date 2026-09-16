rule TTP_XOR_QUAD_CurrentVersionRun_ddff {
  strings:
    $key_ddff = { 8e 90 [2] aa 9e [2] 81 b2 [2] af 90 [2] bb 8b [2] b4 91 [2] aa 8c [2] a8 8d [2] b3 8b [2] af 8c [2] b3 a3 }

  condition:
    any of them
}