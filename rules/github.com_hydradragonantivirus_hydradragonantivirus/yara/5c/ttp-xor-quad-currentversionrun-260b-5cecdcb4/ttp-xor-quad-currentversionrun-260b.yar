rule TTP_XOR_QUAD_CurrentVersionRun_260b {
  strings:
    $key_260b = { 75 64 [2] 51 6a [2] 7a 46 [2] 54 64 [2] 40 7f [2] 4f 65 [2] 51 78 [2] 53 79 [2] 48 7f [2] 54 78 [2] 48 57 }

  condition:
    any of them
}