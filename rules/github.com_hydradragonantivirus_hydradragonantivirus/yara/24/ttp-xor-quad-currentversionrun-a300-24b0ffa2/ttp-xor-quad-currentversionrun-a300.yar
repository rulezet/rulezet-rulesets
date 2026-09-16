rule TTP_XOR_QUAD_CurrentVersionRun_a300 {
  strings:
    $key_a300 = { f0 6f [2] d4 61 [2] ff 4d [2] d1 6f [2] c5 74 [2] ca 6e [2] d4 73 [2] d6 72 [2] cd 74 [2] d1 73 [2] cd 5c }

  condition:
    any of them
}