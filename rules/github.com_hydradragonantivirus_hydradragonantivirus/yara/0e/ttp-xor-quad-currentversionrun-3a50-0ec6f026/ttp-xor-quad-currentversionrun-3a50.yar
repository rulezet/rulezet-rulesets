rule TTP_XOR_QUAD_CurrentVersionRun_3a50 {
  strings:
    $key_3a50 = { 69 3f [2] 4d 31 [2] 66 1d [2] 48 3f [2] 5c 24 [2] 53 3e [2] 4d 23 [2] 4f 22 [2] 54 24 [2] 48 23 [2] 54 0c }

  condition:
    any of them
}