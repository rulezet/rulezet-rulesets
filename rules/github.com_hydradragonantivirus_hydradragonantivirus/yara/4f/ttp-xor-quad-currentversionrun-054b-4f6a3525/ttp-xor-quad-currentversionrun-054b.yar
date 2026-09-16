rule TTP_XOR_QUAD_CurrentVersionRun_054b {
  strings:
    $key_054b = { 56 24 [2] 72 2a [2] 59 06 [2] 77 24 [2] 63 3f [2] 6c 25 [2] 72 38 [2] 70 39 [2] 6b 3f [2] 77 38 [2] 6b 17 }

  condition:
    any of them
}