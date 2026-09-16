rule TTP_XOR_QUAD_CurrentVersionRun_3f1a {
  strings:
    $key_3f1a = { 6c 75 [2] 48 7b [2] 63 57 [2] 4d 75 [2] 59 6e [2] 56 74 [2] 48 69 [2] 4a 68 [2] 51 6e [2] 4d 69 [2] 51 46 }

  condition:
    any of them
}