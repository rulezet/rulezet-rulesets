rule TTP_XOR_QUAD_CurrentVersionRun_2b3b {
  strings:
    $key_2b3b = { 78 54 [2] 5c 5a [2] 77 76 [2] 59 54 [2] 4d 4f [2] 42 55 [2] 5c 48 [2] 5e 49 [2] 45 4f [2] 59 48 [2] 45 67 }

  condition:
    any of them
}