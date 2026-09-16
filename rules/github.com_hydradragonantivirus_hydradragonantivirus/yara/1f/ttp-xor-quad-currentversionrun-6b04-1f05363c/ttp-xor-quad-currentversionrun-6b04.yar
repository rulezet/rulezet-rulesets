rule TTP_XOR_QUAD_CurrentVersionRun_6b04 {
  strings:
    $key_6b04 = { 38 6b [2] 1c 65 [2] 37 49 [2] 19 6b [2] 0d 70 [2] 02 6a [2] 1c 77 [2] 1e 76 [2] 05 70 [2] 19 77 [2] 05 58 }

  condition:
    any of them
}