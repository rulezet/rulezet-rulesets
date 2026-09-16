rule TTP_XOR_QUAD_CurrentVersionRun_3c05 {
  strings:
    $key_3c05 = { 6f 6a [2] 4b 64 [2] 60 48 [2] 4e 6a [2] 5a 71 [2] 55 6b [2] 4b 76 [2] 49 77 [2] 52 71 [2] 4e 76 [2] 52 59 }

  condition:
    any of them
}