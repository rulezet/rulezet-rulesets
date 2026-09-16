rule TTP_XOR_QUAD_CurrentVersionRun_c4ff {
  strings:
    $key_c4ff = { 97 90 [2] b3 9e [2] 98 b2 [2] b6 90 [2] a2 8b [2] ad 91 [2] b3 8c [2] b1 8d [2] aa 8b [2] b6 8c [2] aa a3 }

  condition:
    any of them
}