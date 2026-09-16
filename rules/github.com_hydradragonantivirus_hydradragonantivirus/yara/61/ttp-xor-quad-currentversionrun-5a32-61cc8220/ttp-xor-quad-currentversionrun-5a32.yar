rule TTP_XOR_QUAD_CurrentVersionRun_5a32 {
  strings:
    $key_5a32 = { 09 5d [2] 2d 53 [2] 06 7f [2] 28 5d [2] 3c 46 [2] 33 5c [2] 2d 41 [2] 2f 40 [2] 34 46 [2] 28 41 [2] 34 6e }

  condition:
    any of them
}