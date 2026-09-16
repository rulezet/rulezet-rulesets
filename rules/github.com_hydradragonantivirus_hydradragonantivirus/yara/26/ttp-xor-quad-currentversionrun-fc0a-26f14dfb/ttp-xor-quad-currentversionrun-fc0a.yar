rule TTP_XOR_QUAD_CurrentVersionRun_fc0a {
  strings:
    $key_fc0a = { af 65 [2] 8b 6b [2] a0 47 [2] 8e 65 [2] 9a 7e [2] 95 64 [2] 8b 79 [2] 89 78 [2] 92 7e [2] 8e 79 [2] 92 56 }

  condition:
    any of them
}