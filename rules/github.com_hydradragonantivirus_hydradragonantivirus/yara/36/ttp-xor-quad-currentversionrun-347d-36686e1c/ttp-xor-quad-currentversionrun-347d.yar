rule TTP_XOR_QUAD_CurrentVersionRun_347d {
  strings:
    $key_347d = { 67 12 [2] 43 1c [2] 68 30 [2] 46 12 [2] 52 09 [2] 5d 13 [2] 43 0e [2] 41 0f [2] 5a 09 [2] 46 0e [2] 5a 21 }

  condition:
    any of them
}