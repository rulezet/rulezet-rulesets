rule TTP_XOR_QUAD_CurrentVersionRun_337d {
  strings:
    $key_337d = { 60 12 [2] 44 1c [2] 6f 30 [2] 41 12 [2] 55 09 [2] 5a 13 [2] 44 0e [2] 46 0f [2] 5d 09 [2] 41 0e [2] 5d 21 }

  condition:
    any of them
}