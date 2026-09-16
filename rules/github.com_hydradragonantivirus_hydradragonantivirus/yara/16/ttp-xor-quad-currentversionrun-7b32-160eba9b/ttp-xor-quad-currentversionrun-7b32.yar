rule TTP_XOR_QUAD_CurrentVersionRun_7b32 {
  strings:
    $key_7b32 = { 28 5d [2] 0c 53 [2] 27 7f [2] 09 5d [2] 1d 46 [2] 12 5c [2] 0c 41 [2] 0e 40 [2] 15 46 [2] 09 41 [2] 15 6e }

  condition:
    any of them
}