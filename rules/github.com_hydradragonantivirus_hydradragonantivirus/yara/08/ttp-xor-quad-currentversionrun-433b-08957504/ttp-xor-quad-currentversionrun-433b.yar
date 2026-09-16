rule TTP_XOR_QUAD_CurrentVersionRun_433b {
  strings:
    $key_433b = { 10 54 [2] 34 5a [2] 1f 76 [2] 31 54 [2] 25 4f [2] 2a 55 [2] 34 48 [2] 36 49 [2] 2d 4f [2] 31 48 [2] 2d 67 }

  condition:
    any of them
}