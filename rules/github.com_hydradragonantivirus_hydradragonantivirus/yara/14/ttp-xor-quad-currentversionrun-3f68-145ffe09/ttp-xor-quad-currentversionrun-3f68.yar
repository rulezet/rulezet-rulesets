rule TTP_XOR_QUAD_CurrentVersionRun_3f68 {
  strings:
    $key_3f68 = { 6c 07 [2] 48 09 [2] 63 25 [2] 4d 07 [2] 59 1c [2] 56 06 [2] 48 1b [2] 4a 1a [2] 51 1c [2] 4d 1b [2] 51 34 }

  condition:
    any of them
}