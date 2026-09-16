rule TTP_XOR_QUAD_CurrentVersionRun_3b05 {
  strings:
    $key_3b05 = { 68 6a [2] 4c 64 [2] 67 48 [2] 49 6a [2] 5d 71 [2] 52 6b [2] 4c 76 [2] 4e 77 [2] 55 71 [2] 49 76 [2] 55 59 }

  condition:
    any of them
}