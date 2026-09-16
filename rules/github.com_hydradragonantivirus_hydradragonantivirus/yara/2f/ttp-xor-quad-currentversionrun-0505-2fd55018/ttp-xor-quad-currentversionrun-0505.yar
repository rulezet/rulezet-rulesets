rule TTP_XOR_QUAD_CurrentVersionRun_0505 {
  strings:
    $key_0505 = { 56 6a [2] 72 64 [2] 59 48 [2] 77 6a [2] 63 71 [2] 6c 6b [2] 72 76 [2] 70 77 [2] 6b 71 [2] 77 76 [2] 6b 59 }

  condition:
    any of them
}