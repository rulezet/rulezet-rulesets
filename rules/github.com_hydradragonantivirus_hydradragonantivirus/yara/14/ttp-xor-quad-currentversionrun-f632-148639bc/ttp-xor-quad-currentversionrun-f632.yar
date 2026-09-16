rule TTP_XOR_QUAD_CurrentVersionRun_f632 {
  strings:
    $key_f632 = { a5 5d [2] 81 53 [2] aa 7f [2] 84 5d [2] 90 46 [2] 9f 5c [2] 81 41 [2] 83 40 [2] 98 46 [2] 84 41 [2] 98 6e }

  condition:
    any of them
}