rule TTP_XOR_QUAD_CurrentVersionRun_176b {
  strings:
    $key_176b = { 44 04 [2] 60 0a [2] 4b 26 [2] 65 04 [2] 71 1f [2] 7e 05 [2] 60 18 [2] 62 19 [2] 79 1f [2] 65 18 [2] 79 37 }

  condition:
    any of them
}