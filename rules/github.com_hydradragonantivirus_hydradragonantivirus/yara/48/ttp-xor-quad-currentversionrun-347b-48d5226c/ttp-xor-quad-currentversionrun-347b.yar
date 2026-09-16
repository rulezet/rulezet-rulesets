rule TTP_XOR_QUAD_CurrentVersionRun_347b {
  strings:
    $key_347b = { 67 14 [2] 43 1a [2] 68 36 [2] 46 14 [2] 52 0f [2] 5d 15 [2] 43 08 [2] 41 09 [2] 5a 0f [2] 46 08 [2] 5a 27 }

  condition:
    any of them
}