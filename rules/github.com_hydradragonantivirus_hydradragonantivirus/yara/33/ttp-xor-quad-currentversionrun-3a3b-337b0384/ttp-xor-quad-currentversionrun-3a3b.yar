rule TTP_XOR_QUAD_CurrentVersionRun_3a3b {
  strings:
    $key_3a3b = { 69 54 [2] 4d 5a [2] 66 76 [2] 48 54 [2] 5c 4f [2] 53 55 [2] 4d 48 [2] 4f 49 [2] 54 4f [2] 48 48 [2] 54 67 }

  condition:
    any of them
}