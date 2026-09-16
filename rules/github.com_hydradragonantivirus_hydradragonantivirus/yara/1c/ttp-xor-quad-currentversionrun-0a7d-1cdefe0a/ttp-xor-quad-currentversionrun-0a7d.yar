rule TTP_XOR_QUAD_CurrentVersionRun_0a7d {
  strings:
    $key_0a7d = { 59 12 [2] 7d 1c [2] 56 30 [2] 78 12 [2] 6c 09 [2] 63 13 [2] 7d 0e [2] 7f 0f [2] 64 09 [2] 78 0e [2] 64 21 }

  condition:
    any of them
}