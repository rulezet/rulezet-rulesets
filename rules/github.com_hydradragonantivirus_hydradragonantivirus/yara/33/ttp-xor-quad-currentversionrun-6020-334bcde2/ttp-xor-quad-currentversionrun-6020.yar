rule TTP_XOR_QUAD_CurrentVersionRun_6020 {
  strings:
    $key_6020 = { 33 4f [2] 17 41 [2] 3c 6d [2] 12 4f [2] 06 54 [2] 09 4e [2] 17 53 [2] 15 52 [2] 0e 54 [2] 12 53 [2] 0e 7c }

  condition:
    any of them
}