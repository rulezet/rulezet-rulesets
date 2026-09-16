rule TTP_XOR_QUAD_CurrentVersionRun_3a51 {
  strings:
    $key_3a51 = { 69 3e [2] 4d 30 [2] 66 1c [2] 48 3e [2] 5c 25 [2] 53 3f [2] 4d 22 [2] 4f 23 [2] 54 25 [2] 48 22 [2] 54 0d }

  condition:
    any of them
}