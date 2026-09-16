rule TTP_XOR_QUAD_CurrentVersionRun_271b {
  strings:
    $key_271b = { 74 74 [2] 50 7a [2] 7b 56 [2] 55 74 [2] 41 6f [2] 4e 75 [2] 50 68 [2] 52 69 [2] 49 6f [2] 55 68 [2] 49 47 }

  condition:
    any of them
}