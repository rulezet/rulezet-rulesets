rule TTP_XOR_QUAD_CurrentVersionRun_032a {
  strings:
    $key_032a = { 50 45 [2] 74 4b [2] 5f 67 [2] 71 45 [2] 65 5e [2] 6a 44 [2] 74 59 [2] 76 58 [2] 6d 5e [2] 71 59 [2] 6d 76 }

  condition:
    any of them
}