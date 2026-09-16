rule TTP_XOR_QUAD_CurrentVersionRun_237b {
  strings:
    $key_237b = { 70 14 [2] 54 1a [2] 7f 36 [2] 51 14 [2] 45 0f [2] 4a 15 [2] 54 08 [2] 56 09 [2] 4d 0f [2] 51 08 [2] 4d 27 }

  condition:
    any of them
}