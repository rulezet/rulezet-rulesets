rule TTP_XOR_QUAD_CurrentVersionRun_576b {
  strings:
    $key_576b = { 04 04 [2] 20 0a [2] 0b 26 [2] 25 04 [2] 31 1f [2] 3e 05 [2] 20 18 [2] 22 19 [2] 39 1f [2] 25 18 [2] 39 37 }

  condition:
    any of them
}