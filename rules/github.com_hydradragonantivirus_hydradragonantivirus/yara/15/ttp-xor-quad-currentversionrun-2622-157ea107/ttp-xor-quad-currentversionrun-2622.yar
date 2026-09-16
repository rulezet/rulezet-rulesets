rule TTP_XOR_QUAD_CurrentVersionRun_2622 {
  strings:
    $key_2622 = { 75 4d [2] 51 43 [2] 7a 6f [2] 54 4d [2] 40 56 [2] 4f 4c [2] 51 51 [2] 53 50 [2] 48 56 [2] 54 51 [2] 48 7e }

  condition:
    any of them
}