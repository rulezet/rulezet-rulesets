rule TTP_XOR_QUAD_CurrentVersionRun_0e3b {
  strings:
    $key_0e3b = { 5d 54 [2] 79 5a [2] 52 76 [2] 7c 54 [2] 68 4f [2] 67 55 [2] 79 48 [2] 7b 49 [2] 60 4f [2] 7c 48 [2] 60 67 }

  condition:
    any of them
}