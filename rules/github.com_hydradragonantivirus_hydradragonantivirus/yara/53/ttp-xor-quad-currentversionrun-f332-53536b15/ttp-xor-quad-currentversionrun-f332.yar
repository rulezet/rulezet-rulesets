rule TTP_XOR_QUAD_CurrentVersionRun_f332 {
  strings:
    $key_f332 = { a0 5d [2] 84 53 [2] af 7f [2] 81 5d [2] 95 46 [2] 9a 5c [2] 84 41 [2] 86 40 [2] 9d 46 [2] 81 41 [2] 9d 6e }

  condition:
    any of them
}