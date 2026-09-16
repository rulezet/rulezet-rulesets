rule TTP_XOR_QUAD_CurrentVersionRun_6a3b {
  strings:
    $key_6a3b = { 39 54 [2] 1d 5a [2] 36 76 [2] 18 54 [2] 0c 4f [2] 03 55 [2] 1d 48 [2] 1f 49 [2] 04 4f [2] 18 48 [2] 04 67 }

  condition:
    any of them
}