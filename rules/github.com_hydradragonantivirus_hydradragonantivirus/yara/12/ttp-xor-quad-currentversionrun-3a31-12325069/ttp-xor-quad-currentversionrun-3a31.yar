rule TTP_XOR_QUAD_CurrentVersionRun_3a31 {
  strings:
    $key_3a31 = { 69 5e [2] 4d 50 [2] 66 7c [2] 48 5e [2] 5c 45 [2] 53 5f [2] 4d 42 [2] 4f 43 [2] 54 45 [2] 48 42 [2] 54 6d }

  condition:
    any of them
}