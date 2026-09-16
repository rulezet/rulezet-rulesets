rule TTP_XOR_QUAD_CurrentVersionRun_323b {
  strings:
    $key_323b = { 61 54 [2] 45 5a [2] 6e 76 [2] 40 54 [2] 54 4f [2] 5b 55 [2] 45 48 [2] 47 49 [2] 5c 4f [2] 40 48 [2] 5c 67 }

  condition:
    any of them
}