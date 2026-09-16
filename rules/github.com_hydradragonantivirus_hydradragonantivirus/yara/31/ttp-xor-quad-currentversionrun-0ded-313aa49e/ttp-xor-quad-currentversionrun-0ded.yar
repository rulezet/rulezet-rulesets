rule TTP_XOR_QUAD_CurrentVersionRun_0ded {
  strings:
    $key_0ded = { 5e 82 [2] 7a 8c [2] 51 a0 [2] 7f 82 [2] 6b 99 [2] 64 83 [2] 7a 9e [2] 78 9f [2] 63 99 [2] 7f 9e [2] 63 b1 }

  condition:
    any of them
}