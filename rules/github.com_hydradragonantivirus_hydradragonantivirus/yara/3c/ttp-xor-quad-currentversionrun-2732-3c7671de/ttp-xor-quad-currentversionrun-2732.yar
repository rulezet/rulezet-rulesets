rule TTP_XOR_QUAD_CurrentVersionRun_2732 {
  strings:
    $key_2732 = { 74 5d [2] 50 53 [2] 7b 7f [2] 55 5d [2] 41 46 [2] 4e 5c [2] 50 41 [2] 52 40 [2] 49 46 [2] 55 41 [2] 49 6e }

  condition:
    any of them
}