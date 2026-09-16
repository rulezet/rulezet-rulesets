rule TTP_XOR_QUAD_CurrentVersionRun_3f1b {
  strings:
    $key_3f1b = { 6c 74 [2] 48 7a [2] 63 56 [2] 4d 74 [2] 59 6f [2] 56 75 [2] 48 68 [2] 4a 69 [2] 51 6f [2] 4d 68 [2] 51 47 }

  condition:
    any of them
}