rule TTP_XOR_QUAD_CurrentVersionRun_262b {
  strings:
    $key_262b = { 75 44 [2] 51 4a [2] 7a 66 [2] 54 44 [2] 40 5f [2] 4f 45 [2] 51 58 [2] 53 59 [2] 48 5f [2] 54 58 [2] 48 77 }

  condition:
    any of them
}