rule TTP_XOR_QUAD_CurrentVersionRun_0f7a {
  strings:
    $key_0f7a = { 5c 15 [2] 78 1b [2] 53 37 [2] 7d 15 [2] 69 0e [2] 66 14 [2] 78 09 [2] 7a 08 [2] 61 0e [2] 7d 09 [2] 61 26 }

  condition:
    any of them
}