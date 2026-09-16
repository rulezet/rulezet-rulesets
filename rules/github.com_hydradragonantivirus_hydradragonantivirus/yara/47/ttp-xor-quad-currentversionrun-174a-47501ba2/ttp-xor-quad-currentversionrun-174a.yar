rule TTP_XOR_QUAD_CurrentVersionRun_174a {
  strings:
    $key_174a = { 44 25 [2] 60 2b [2] 4b 07 [2] 65 25 [2] 71 3e [2] 7e 24 [2] 60 39 [2] 62 38 [2] 79 3e [2] 65 39 [2] 79 16 }

  condition:
    any of them
}