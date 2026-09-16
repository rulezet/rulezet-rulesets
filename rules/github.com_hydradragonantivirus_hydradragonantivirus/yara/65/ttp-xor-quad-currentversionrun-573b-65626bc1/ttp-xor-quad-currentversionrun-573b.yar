rule TTP_XOR_QUAD_CurrentVersionRun_573b {
  strings:
    $key_573b = { 04 54 [2] 20 5a [2] 0b 76 [2] 25 54 [2] 31 4f [2] 3e 55 [2] 20 48 [2] 22 49 [2] 39 4f [2] 25 48 [2] 39 67 }

  condition:
    any of them
}