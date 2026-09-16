rule TTP_XOR_QUAD_CurrentVersionRun_232b {
  strings:
    $key_232b = { 70 44 [2] 54 4a [2] 7f 66 [2] 51 44 [2] 45 5f [2] 4a 45 [2] 54 58 [2] 56 59 [2] 4d 5f [2] 51 58 [2] 4d 77 }

  condition:
    any of them
}