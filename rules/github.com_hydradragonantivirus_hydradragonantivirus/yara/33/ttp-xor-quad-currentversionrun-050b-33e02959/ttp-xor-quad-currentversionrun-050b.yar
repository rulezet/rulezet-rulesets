rule TTP_XOR_QUAD_CurrentVersionRun_050b {
  strings:
    $key_050b = { 56 64 [2] 72 6a [2] 59 46 [2] 77 64 [2] 63 7f [2] 6c 65 [2] 72 78 [2] 70 79 [2] 6b 7f [2] 77 78 [2] 6b 57 }

  condition:
    any of them
}