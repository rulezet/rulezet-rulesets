rule TTP_XOR_QUAD_CurrentVersionRun_0a7a {
  strings:
    $key_0a7a = { 59 15 [2] 7d 1b [2] 56 37 [2] 78 15 [2] 6c 0e [2] 63 14 [2] 7d 09 [2] 7f 08 [2] 64 0e [2] 78 09 [2] 64 26 }

  condition:
    any of them
}