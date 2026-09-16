rule TTP_XOR_QUAD_CurrentVersionRun_fc2f {
  strings:
    $key_fc2f = { af 40 [2] 8b 4e [2] a0 62 [2] 8e 40 [2] 9a 5b [2] 95 41 [2] 8b 5c [2] 89 5d [2] 92 5b [2] 8e 5c [2] 92 73 }

  condition:
    any of them
}