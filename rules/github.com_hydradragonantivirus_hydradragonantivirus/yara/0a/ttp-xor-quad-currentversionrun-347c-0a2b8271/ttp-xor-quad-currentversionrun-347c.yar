rule TTP_XOR_QUAD_CurrentVersionRun_347c {
  strings:
    $key_347c = { 67 13 [2] 43 1d [2] 68 31 [2] 46 13 [2] 52 08 [2] 5d 12 [2] 43 0f [2] 41 0e [2] 5a 08 [2] 46 0f [2] 5a 20 }

  condition:
    any of them
}