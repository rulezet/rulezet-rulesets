rule TTP_XOR_QUAD_CurrentVersionRun_3421 {
  strings:
    $key_3421 = { 67 4e [2] 43 40 [2] 68 6c [2] 46 4e [2] 52 55 [2] 5d 4f [2] 43 52 [2] 41 53 [2] 5a 55 [2] 46 52 [2] 5a 7d }

  condition:
    any of them
}