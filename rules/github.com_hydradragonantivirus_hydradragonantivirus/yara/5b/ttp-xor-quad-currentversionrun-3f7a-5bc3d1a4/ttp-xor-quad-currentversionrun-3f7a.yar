rule TTP_XOR_QUAD_CurrentVersionRun_3f7a {
  strings:
    $key_3f7a = { 6c 15 [2] 48 1b [2] 63 37 [2] 4d 15 [2] 59 0e [2] 56 14 [2] 48 09 [2] 4a 08 [2] 51 0e [2] 4d 09 [2] 51 26 }

  condition:
    any of them
}