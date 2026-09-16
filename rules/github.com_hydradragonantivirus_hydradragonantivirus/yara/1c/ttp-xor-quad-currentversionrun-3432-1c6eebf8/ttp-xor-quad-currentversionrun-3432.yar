rule TTP_XOR_QUAD_CurrentVersionRun_3432 {
  strings:
    $key_3432 = { 67 5d [2] 43 53 [2] 68 7f [2] 46 5d [2] 52 46 [2] 5d 5c [2] 43 41 [2] 41 40 [2] 5a 46 [2] 46 41 [2] 5a 6e }

  condition:
    any of them
}