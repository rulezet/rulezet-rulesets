rule TTP_XOR_QUAD_CurrentVersionRun_026b {
  strings:
    $key_026b = { 51 04 [2] 75 0a [2] 5e 26 [2] 70 04 [2] 64 1f [2] 6b 05 [2] 75 18 [2] 77 19 [2] 6c 1f [2] 70 18 [2] 6c 37 }

  condition:
    any of them
}