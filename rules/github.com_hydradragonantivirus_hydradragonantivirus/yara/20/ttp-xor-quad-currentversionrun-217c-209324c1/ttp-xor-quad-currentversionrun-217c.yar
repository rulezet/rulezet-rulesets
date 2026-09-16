rule TTP_XOR_QUAD_CurrentVersionRun_217c {
  strings:
    $key_217c = { 72 13 [2] 56 1d [2] 7d 31 [2] 53 13 [2] 47 08 [2] 48 12 [2] 56 0f [2] 54 0e [2] 4f 08 [2] 53 0f [2] 4f 20 }

  condition:
    any of them
}