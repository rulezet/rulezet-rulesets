rule TTP_XOR_QUAD_CurrentVersionRun_401b {
  strings:
    $key_401b = { 13 74 [2] 37 7a [2] 1c 56 [2] 32 74 [2] 26 6f [2] 29 75 [2] 37 68 [2] 35 69 [2] 2e 6f [2] 32 68 [2] 2e 47 }

  condition:
    any of them
}