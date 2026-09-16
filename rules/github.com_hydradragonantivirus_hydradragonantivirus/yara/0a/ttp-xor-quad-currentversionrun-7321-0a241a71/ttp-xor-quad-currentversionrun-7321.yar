rule TTP_XOR_QUAD_CurrentVersionRun_7321 {
  strings:
    $key_7321 = { 20 4e [2] 04 40 [2] 2f 6c [2] 01 4e [2] 15 55 [2] 1a 4f [2] 04 52 [2] 06 53 [2] 1d 55 [2] 01 52 [2] 1d 7d }

  condition:
    any of them
}