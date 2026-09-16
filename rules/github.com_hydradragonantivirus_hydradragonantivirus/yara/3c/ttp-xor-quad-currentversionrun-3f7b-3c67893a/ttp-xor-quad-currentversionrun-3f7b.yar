rule TTP_XOR_QUAD_CurrentVersionRun_3f7b {
  strings:
    $key_3f7b = { 6c 14 [2] 48 1a [2] 63 36 [2] 4d 14 [2] 59 0f [2] 56 15 [2] 48 08 [2] 4a 09 [2] 51 0f [2] 4d 08 [2] 51 27 }

  condition:
    any of them
}