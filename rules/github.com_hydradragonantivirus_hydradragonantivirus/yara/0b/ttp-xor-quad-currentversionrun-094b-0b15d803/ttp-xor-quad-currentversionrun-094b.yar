rule TTP_XOR_QUAD_CurrentVersionRun_094b {
  strings:
    $key_094b = { 5a 24 [2] 7e 2a [2] 55 06 [2] 7b 24 [2] 6f 3f [2] 60 25 [2] 7e 38 [2] 7c 39 [2] 67 3f [2] 7b 38 [2] 67 17 }

  condition:
    any of them
}