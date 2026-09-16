rule TTP_XOR_QUAD_CurrentVersionRun_fc0c {
  strings:
    $key_fc0c = { af 63 [2] 8b 6d [2] a0 41 [2] 8e 63 [2] 9a 78 [2] 95 62 [2] 8b 7f [2] 89 7e [2] 92 78 [2] 8e 7f [2] 92 50 }

  condition:
    any of them
}