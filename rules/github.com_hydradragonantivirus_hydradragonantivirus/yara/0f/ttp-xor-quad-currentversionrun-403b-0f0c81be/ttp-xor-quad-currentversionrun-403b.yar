rule TTP_XOR_QUAD_CurrentVersionRun_403b {
  strings:
    $key_403b = { 13 54 [2] 37 5a [2] 1c 76 [2] 32 54 [2] 26 4f [2] 29 55 [2] 37 48 [2] 35 49 [2] 2e 4f [2] 32 48 [2] 2e 67 }

  condition:
    any of them
}