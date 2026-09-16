rule TTP_XOR_QUAD_CurrentVersionRun_6afb {
  strings:
    $key_6afb = { 39 94 [2] 1d 9a [2] 36 b6 [2] 18 94 [2] 0c 8f [2] 03 95 [2] 1d 88 [2] 1f 89 [2] 04 8f [2] 18 88 [2] 04 a7 }

  condition:
    any of them
}