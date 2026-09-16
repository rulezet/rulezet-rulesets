rule TTP_XOR_QUAD_CurrentVersionRun_320b {
  strings:
    $key_320b = { 61 64 [2] 45 6a [2] 6e 46 [2] 40 64 [2] 54 7f [2] 5b 65 [2] 45 78 [2] 47 79 [2] 5c 7f [2] 40 78 [2] 5c 57 }

  condition:
    any of them
}