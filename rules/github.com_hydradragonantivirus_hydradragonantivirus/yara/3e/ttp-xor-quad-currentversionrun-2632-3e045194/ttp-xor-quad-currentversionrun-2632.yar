rule TTP_XOR_QUAD_CurrentVersionRun_2632 {
  strings:
    $key_2632 = { 75 5d [2] 51 53 [2] 7a 7f [2] 54 5d [2] 40 46 [2] 4f 5c [2] 51 41 [2] 53 40 [2] 48 46 [2] 54 41 [2] 48 6e }

  condition:
    any of them
}