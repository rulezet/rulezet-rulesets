rule TTP_XOR_QUAD_CurrentVersionRun_d8ef {
  strings:
    $key_d8ef = { 8b 80 [2] af 8e [2] 84 a2 [2] aa 80 [2] be 9b [2] b1 81 [2] af 9c [2] ad 9d [2] b6 9b [2] aa 9c [2] b6 b3 }

  condition:
    any of them
}