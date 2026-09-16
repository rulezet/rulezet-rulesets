rule TTP_XOR_QUAD_CurrentVersionRun_6505 {
  strings:
    $key_6505 = { 36 6a [2] 12 64 [2] 39 48 [2] 17 6a [2] 03 71 [2] 0c 6b [2] 12 76 [2] 10 77 [2] 0b 71 [2] 17 76 [2] 0b 59 }

  condition:
    any of them
}