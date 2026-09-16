rule TTP_XOR_QUAD_CurrentVersionRun_2101 {
  strings:
    $key_2101 = { 72 6e [2] 56 60 [2] 7d 4c [2] 53 6e [2] 47 75 [2] 48 6f [2] 56 72 [2] 54 73 [2] 4f 75 [2] 53 72 [2] 4f 5d }

  condition:
    any of them
}