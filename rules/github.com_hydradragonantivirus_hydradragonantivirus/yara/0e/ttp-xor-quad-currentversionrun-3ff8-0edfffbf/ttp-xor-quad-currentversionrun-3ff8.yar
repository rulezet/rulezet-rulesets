rule TTP_XOR_QUAD_CurrentVersionRun_3ff8 {
  strings:
    $key_3ff8 = { 6c 97 [2] 48 99 [2] 63 b5 [2] 4d 97 [2] 59 8c [2] 56 96 [2] 48 8b [2] 4a 8a [2] 51 8c [2] 4d 8b [2] 51 a4 }

  condition:
    any of them
}