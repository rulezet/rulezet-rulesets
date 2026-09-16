rule TTP_XOR_QUAD_CurrentVersionRun_663b {
  strings:
    $key_663b = { 35 54 [2] 11 5a [2] 3a 76 [2] 14 54 [2] 00 4f [2] 0f 55 [2] 11 48 [2] 13 49 [2] 08 4f [2] 14 48 [2] 08 67 }

  condition:
    any of them
}