rule TTP_XOR_QUAD_CurrentVersionRun_2129 {
  strings:
    $key_2129 = { 72 46 [2] 56 48 [2] 7d 64 [2] 53 46 [2] 47 5d [2] 48 47 [2] 56 5a [2] 54 5b [2] 4f 5d [2] 53 5a [2] 4f 75 }

  condition:
    any of them
}