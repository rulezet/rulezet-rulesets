rule TTP_XOR_QUAD_CurrentVersionRun_fc00 {
  strings:
    $key_fc00 = { af 6f [2] 8b 61 [2] a0 4d [2] 8e 6f [2] 9a 74 [2] 95 6e [2] 8b 73 [2] 89 72 [2] 92 74 [2] 8e 73 [2] 92 5c }

  condition:
    any of them
}