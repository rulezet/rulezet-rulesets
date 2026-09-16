rule TTP_XOR_QUAD_CurrentVersionRun_6021 {
  strings:
    $key_6021 = { 33 4e [2] 17 40 [2] 3c 6c [2] 12 4e [2] 06 55 [2] 09 4f [2] 17 52 [2] 15 53 [2] 0e 55 [2] 12 52 [2] 0e 7d }

  condition:
    any of them
}