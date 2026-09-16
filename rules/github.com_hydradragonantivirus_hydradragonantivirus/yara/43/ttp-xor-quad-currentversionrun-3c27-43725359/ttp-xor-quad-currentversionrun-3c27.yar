rule TTP_XOR_QUAD_CurrentVersionRun_3c27 {
  strings:
    $key_3c27 = { 6f 48 [2] 4b 46 [2] 60 6a [2] 4e 48 [2] 5a 53 [2] 55 49 [2] 4b 54 [2] 49 55 [2] 52 53 [2] 4e 54 [2] 52 7b }

  condition:
    any of them
}