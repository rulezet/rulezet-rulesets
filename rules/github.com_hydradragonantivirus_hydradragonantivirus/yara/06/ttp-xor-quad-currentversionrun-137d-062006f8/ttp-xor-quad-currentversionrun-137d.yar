rule TTP_XOR_QUAD_CurrentVersionRun_137d {
  strings:
    $key_137d = { 40 12 [2] 64 1c [2] 4f 30 [2] 61 12 [2] 75 09 [2] 7a 13 [2] 64 0e [2] 66 0f [2] 7d 09 [2] 61 0e [2] 7d 21 }

  condition:
    any of them
}