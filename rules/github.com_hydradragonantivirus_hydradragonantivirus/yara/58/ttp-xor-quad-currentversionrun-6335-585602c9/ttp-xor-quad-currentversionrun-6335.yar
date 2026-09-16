rule TTP_XOR_QUAD_CurrentVersionRun_6335 {
  strings:
    $key_6335 = { 30 5a [2] 14 54 [2] 3f 78 [2] 11 5a [2] 05 41 [2] 0a 5b [2] 14 46 [2] 16 47 [2] 0d 41 [2] 11 46 [2] 0d 69 }

  condition:
    any of them
}