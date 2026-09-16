rule TTP_XOR_QUAD_CurrentVersionRun_3f27 {
  strings:
    $key_3f27 = { 6c 48 [2] 48 46 [2] 63 6a [2] 4d 48 [2] 59 53 [2] 56 49 [2] 48 54 [2] 4a 55 [2] 51 53 [2] 4d 54 [2] 51 7b }

  condition:
    any of them
}