rule TTP_XOR_QUAD_CurrentVersionRun_250b {
  strings:
    $key_250b = { 76 64 [2] 52 6a [2] 79 46 [2] 57 64 [2] 43 7f [2] 4c 65 [2] 52 78 [2] 50 79 [2] 4b 7f [2] 57 78 [2] 4b 57 }

  condition:
    any of them
}