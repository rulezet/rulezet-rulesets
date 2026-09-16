rule TTP_XOR_QUAD_CurrentVersionRun_1432 {
  strings:
    $key_1432 = { 47 5d [2] 63 53 [2] 48 7f [2] 66 5d [2] 72 46 [2] 7d 5c [2] 63 41 [2] 61 40 [2] 7a 46 [2] 66 41 [2] 7a 6e }

  condition:
    any of them
}