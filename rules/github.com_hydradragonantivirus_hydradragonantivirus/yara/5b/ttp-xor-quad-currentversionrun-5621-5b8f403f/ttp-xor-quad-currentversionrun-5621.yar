rule TTP_XOR_QUAD_CurrentVersionRun_5621 {
  strings:
    $key_5621 = { 05 4e [2] 21 40 [2] 0a 6c [2] 24 4e [2] 30 55 [2] 3f 4f [2] 21 52 [2] 23 53 [2] 38 55 [2] 24 52 [2] 38 7d }

  condition:
    any of them
}