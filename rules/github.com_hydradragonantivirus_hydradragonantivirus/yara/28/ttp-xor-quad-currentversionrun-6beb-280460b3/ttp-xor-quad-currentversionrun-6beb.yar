rule TTP_XOR_QUAD_CurrentVersionRun_6beb {
  strings:
    $key_6beb = { 38 84 [2] 1c 8a [2] 37 a6 [2] 19 84 [2] 0d 9f [2] 02 85 [2] 1c 98 [2] 1e 99 [2] 05 9f [2] 19 98 [2] 05 b7 }

  condition:
    any of them
}