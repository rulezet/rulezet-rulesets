rule TTP_XOR_QUAD_CurrentVersionRun_213b {
  strings:
    $key_213b = { 72 54 [2] 56 5a [2] 7d 76 [2] 53 54 [2] 47 4f [2] 48 55 [2] 56 48 [2] 54 49 [2] 4f 4f [2] 53 48 [2] 4f 67 }

  condition:
    any of them
}