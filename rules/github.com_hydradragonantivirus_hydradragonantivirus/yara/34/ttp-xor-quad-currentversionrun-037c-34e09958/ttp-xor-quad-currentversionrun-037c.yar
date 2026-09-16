rule TTP_XOR_QUAD_CurrentVersionRun_037c {
  strings:
    $key_037c = { 50 13 [2] 74 1d [2] 5f 31 [2] 71 13 [2] 65 08 [2] 6a 12 [2] 74 0f [2] 76 0e [2] 6d 08 [2] 71 0f [2] 6d 20 }

  condition:
    any of them
}