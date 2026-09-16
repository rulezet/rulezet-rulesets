rule TTP_XOR_QUAD_CurrentVersionRun_273b {
  strings:
    $key_273b = { 74 54 [2] 50 5a [2] 7b 76 [2] 55 54 [2] 41 4f [2] 4e 55 [2] 50 48 [2] 52 49 [2] 49 4f [2] 55 48 [2] 49 67 }

  condition:
    any of them
}