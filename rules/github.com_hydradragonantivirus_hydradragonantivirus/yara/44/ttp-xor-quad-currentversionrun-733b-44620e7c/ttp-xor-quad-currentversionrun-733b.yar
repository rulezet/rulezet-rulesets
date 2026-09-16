rule TTP_XOR_QUAD_CurrentVersionRun_733b {
  strings:
    $key_733b = { 20 54 [2] 04 5a [2] 2f 76 [2] 01 54 [2] 15 4f [2] 1a 55 [2] 04 48 [2] 06 49 [2] 1d 4f [2] 01 48 [2] 1d 67 }

  condition:
    any of them
}