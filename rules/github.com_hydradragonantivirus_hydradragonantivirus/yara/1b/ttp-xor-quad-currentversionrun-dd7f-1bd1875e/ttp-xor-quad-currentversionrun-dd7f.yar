rule TTP_XOR_QUAD_CurrentVersionRun_dd7f {
  strings:
    $key_dd7f = { 8e 10 [2] aa 1e [2] 81 32 [2] af 10 [2] bb 0b [2] b4 11 [2] aa 0c [2] a8 0d [2] b3 0b [2] af 0c [2] b3 23 }

  condition:
    any of them
}