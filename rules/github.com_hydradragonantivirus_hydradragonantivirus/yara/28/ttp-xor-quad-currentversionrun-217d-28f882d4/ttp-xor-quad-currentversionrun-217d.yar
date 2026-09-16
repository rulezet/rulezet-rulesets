rule TTP_XOR_QUAD_CurrentVersionRun_217d {
  strings:
    $key_217d = { 72 12 [2] 56 1c [2] 7d 30 [2] 53 12 [2] 47 09 [2] 48 13 [2] 56 0e [2] 54 0f [2] 4f 09 [2] 53 0e [2] 4f 21 }

  condition:
    any of them
}