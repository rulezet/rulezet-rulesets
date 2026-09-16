rule TTP_XOR_QUAD_CurrentVersionRun_e232 {
  strings:
    $key_e232 = { b1 5d [2] 95 53 [2] be 7f [2] 90 5d [2] 84 46 [2] 8b 5c [2] 95 41 [2] 97 40 [2] 8c 46 [2] 90 41 [2] 8c 6e }

  condition:
    any of them
}