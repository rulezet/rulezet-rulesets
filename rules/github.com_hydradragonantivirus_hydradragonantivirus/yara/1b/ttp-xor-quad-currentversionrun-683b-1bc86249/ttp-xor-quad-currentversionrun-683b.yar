rule TTP_XOR_QUAD_CurrentVersionRun_683b {
  strings:
    $key_683b = { 3b 54 [2] 1f 5a [2] 34 76 [2] 1a 54 [2] 0e 4f [2] 01 55 [2] 1f 48 [2] 1d 49 [2] 06 4f [2] 1a 48 [2] 06 67 }

  condition:
    any of them
}