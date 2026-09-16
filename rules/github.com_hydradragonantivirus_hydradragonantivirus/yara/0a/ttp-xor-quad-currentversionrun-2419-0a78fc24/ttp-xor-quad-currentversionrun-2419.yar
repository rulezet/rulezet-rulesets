rule TTP_XOR_QUAD_CurrentVersionRun_2419 {
  strings:
    $key_2419 = { 77 76 [2] 53 78 [2] 78 54 [2] 56 76 [2] 42 6d [2] 4d 77 [2] 53 6a [2] 51 6b [2] 4a 6d [2] 56 6a [2] 4a 45 }

  condition:
    any of them
}