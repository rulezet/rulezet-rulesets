rule TTP_XOR_QUAD_CurrentVersionRun_4e32 {
  strings:
    $key_4e32 = { 1d 5d [2] 39 53 [2] 12 7f [2] 3c 5d [2] 28 46 [2] 27 5c [2] 39 41 [2] 3b 40 [2] 20 46 [2] 3c 41 [2] 20 6e }

  condition:
    any of them
}