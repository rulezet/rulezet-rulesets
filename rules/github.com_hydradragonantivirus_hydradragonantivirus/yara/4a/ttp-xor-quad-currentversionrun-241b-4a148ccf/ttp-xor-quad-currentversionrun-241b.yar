rule TTP_XOR_QUAD_CurrentVersionRun_241b {
  strings:
    $key_241b = { 77 74 [2] 53 7a [2] 78 56 [2] 56 74 [2] 42 6f [2] 4d 75 [2] 53 68 [2] 51 69 [2] 4a 6f [2] 56 68 [2] 4a 47 }

  condition:
    any of them
}