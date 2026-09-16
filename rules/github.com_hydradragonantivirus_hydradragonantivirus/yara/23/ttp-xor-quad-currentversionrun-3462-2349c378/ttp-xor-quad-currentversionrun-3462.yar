rule TTP_XOR_QUAD_CurrentVersionRun_3462 {
  strings:
    $key_3462 = { 67 0d [2] 43 03 [2] 68 2f [2] 46 0d [2] 52 16 [2] 5d 0c [2] 43 11 [2] 41 10 [2] 5a 16 [2] 46 11 [2] 5a 3e }

  condition:
    any of them
}