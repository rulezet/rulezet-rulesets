rule TTP_XOR_QUAD_CurrentVersionRun_2032 {
  strings:
    $key_2032 = { 73 5d [2] 57 53 [2] 7c 7f [2] 52 5d [2] 46 46 [2] 49 5c [2] 57 41 [2] 55 40 [2] 4e 46 [2] 52 41 [2] 4e 6e }

  condition:
    any of them
}