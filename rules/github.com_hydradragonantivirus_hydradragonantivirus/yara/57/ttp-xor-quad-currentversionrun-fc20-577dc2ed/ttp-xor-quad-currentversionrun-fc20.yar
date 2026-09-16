rule TTP_XOR_QUAD_CurrentVersionRun_fc20 {
  strings:
    $key_fc20 = { af 4f [2] 8b 41 [2] a0 6d [2] 8e 4f [2] 9a 54 [2] 95 4e [2] 8b 53 [2] 89 52 [2] 92 54 [2] 8e 53 [2] 92 7c }

  condition:
    any of them
}