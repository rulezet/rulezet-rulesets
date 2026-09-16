rule TTP_XOR_QUAD_CurrentVersionRun_2439 {
  strings:
    $key_2439 = { 77 56 [2] 53 58 [2] 78 74 [2] 56 56 [2] 42 4d [2] 4d 57 [2] 53 4a [2] 51 4b [2] 4a 4d [2] 56 4a [2] 4a 65 }

  condition:
    any of them
}