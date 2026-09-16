rule TTP_XOR_QUAD_CurrentVersionRun_7021 {
  strings:
    $key_7021 = { 23 4e [2] 07 40 [2] 2c 6c [2] 02 4e [2] 16 55 [2] 19 4f [2] 07 52 [2] 05 53 [2] 1e 55 [2] 02 52 [2] 1e 7d }

  condition:
    any of them
}