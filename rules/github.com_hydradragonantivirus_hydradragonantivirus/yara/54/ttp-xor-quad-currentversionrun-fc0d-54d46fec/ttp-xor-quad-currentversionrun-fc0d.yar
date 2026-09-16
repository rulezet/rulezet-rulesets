rule TTP_XOR_QUAD_CurrentVersionRun_fc0d {
  strings:
    $key_fc0d = { af 62 [2] 8b 6c [2] a0 40 [2] 8e 62 [2] 9a 79 [2] 95 63 [2] 8b 7e [2] 89 7f [2] 92 79 [2] 8e 7e [2] 92 51 }

  condition:
    any of them
}