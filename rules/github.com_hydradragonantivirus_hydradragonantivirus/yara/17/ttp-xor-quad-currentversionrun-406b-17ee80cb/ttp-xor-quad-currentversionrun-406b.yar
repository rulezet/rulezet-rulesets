rule TTP_XOR_QUAD_CurrentVersionRun_406b {
  strings:
    $key_406b = { 13 04 [2] 37 0a [2] 1c 26 [2] 32 04 [2] 26 1f [2] 29 05 [2] 37 18 [2] 35 19 [2] 2e 1f [2] 32 18 [2] 2e 37 }

  condition:
    any of them
}