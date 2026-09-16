rule TTP_XOR_QUAD_CurrentVersionRun_337c {
  strings:
    $key_337c = { 60 13 [2] 44 1d [2] 6f 31 [2] 41 13 [2] 55 08 [2] 5a 12 [2] 44 0f [2] 46 0e [2] 5d 08 [2] 41 0f [2] 5d 20 }

  condition:
    any of them
}