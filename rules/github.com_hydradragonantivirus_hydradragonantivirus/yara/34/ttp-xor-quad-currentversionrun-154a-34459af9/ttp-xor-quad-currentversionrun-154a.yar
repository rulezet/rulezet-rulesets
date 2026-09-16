rule TTP_XOR_QUAD_CurrentVersionRun_154a {
  strings:
    $key_154a = { 46 25 [2] 62 2b [2] 49 07 [2] 67 25 [2] 73 3e [2] 7c 24 [2] 62 39 [2] 60 38 [2] 7b 3e [2] 67 39 [2] 7b 16 }

  condition:
    any of them
}