rule TTP_XOR_QUAD_CurrentVersionRun_250a {
  strings:
    $key_250a = { 76 65 [2] 52 6b [2] 79 47 [2] 57 65 [2] 43 7e [2] 4c 64 [2] 52 79 [2] 50 78 [2] 4b 7e [2] 57 79 [2] 4b 56 }

  condition:
    any of them
}