rule TTP_XOR_QUAD_CurrentVersionRun_2332 {
  strings:
    $key_2332 = { 70 5d [2] 54 53 [2] 7f 7f [2] 51 5d [2] 45 46 [2] 4a 5c [2] 54 41 [2] 56 40 [2] 4d 46 [2] 51 41 [2] 4d 6e }

  condition:
    any of them
}