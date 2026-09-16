rule TTP_XOR_QUAD_CurrentVersionRun_7a6a {
  strings:
    $key_7a6a = { 29 05 [2] 0d 0b [2] 26 27 [2] 08 05 [2] 1c 1e [2] 13 04 [2] 0d 19 [2] 0f 18 [2] 14 1e [2] 08 19 [2] 14 36 }

  condition:
    any of them
}