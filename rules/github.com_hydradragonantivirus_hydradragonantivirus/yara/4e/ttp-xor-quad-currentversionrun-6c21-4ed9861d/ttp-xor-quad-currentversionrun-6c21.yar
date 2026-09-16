rule TTP_XOR_QUAD_CurrentVersionRun_6c21 {
  strings:
    $key_6c21 = { 3f 4e [2] 1b 40 [2] 30 6c [2] 1e 4e [2] 0a 55 [2] 05 4f [2] 1b 52 [2] 19 53 [2] 02 55 [2] 1e 52 [2] 02 7d }

  condition:
    any of them
}