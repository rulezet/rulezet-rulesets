rule TTP_XOR_QUAD_CurrentVersionRun_d87f {
  strings:
    $key_d87f = { 8b 10 [2] af 1e [2] 84 32 [2] aa 10 [2] be 0b [2] b1 11 [2] af 0c [2] ad 0d [2] b6 0b [2] aa 0c [2] b6 23 }

  condition:
    any of them
}