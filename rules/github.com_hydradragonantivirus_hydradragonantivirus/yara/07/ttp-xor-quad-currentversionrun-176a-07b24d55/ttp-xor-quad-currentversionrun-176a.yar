rule TTP_XOR_QUAD_CurrentVersionRun_176a {
  strings:
    $key_176a = { 44 05 [2] 60 0b [2] 4b 27 [2] 65 05 [2] 71 1e [2] 7e 04 [2] 60 19 [2] 62 18 [2] 79 1e [2] 65 19 [2] 79 36 }

  condition:
    any of them
}