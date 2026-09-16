rule TTP_XOR_QUAD_CurrentVersionRun_3c0b {
  strings:
    $key_3c0b = { 6f 64 [2] 4b 6a [2] 60 46 [2] 4e 64 [2] 5a 7f [2] 55 65 [2] 4b 78 [2] 49 79 [2] 52 7f [2] 4e 78 [2] 52 57 }

  condition:
    any of them
}