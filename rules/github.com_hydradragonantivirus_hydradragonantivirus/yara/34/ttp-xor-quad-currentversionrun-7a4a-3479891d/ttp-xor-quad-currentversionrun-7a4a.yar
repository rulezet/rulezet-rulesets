rule TTP_XOR_QUAD_CurrentVersionRun_7a4a {
  strings:
    $key_7a4a = { 29 25 [2] 0d 2b [2] 26 07 [2] 08 25 [2] 1c 3e [2] 13 24 [2] 0d 39 [2] 0f 38 [2] 14 3e [2] 08 39 [2] 14 16 }

  condition:
    any of them
}