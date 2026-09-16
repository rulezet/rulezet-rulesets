rule TTP_XOR_QUAD_CurrentVersionRun_6be4 {
  strings:
    $key_6be4 = { 38 8b [2] 1c 85 [2] 37 a9 [2] 19 8b [2] 0d 90 [2] 02 8a [2] 1c 97 [2] 1e 96 [2] 05 90 [2] 19 97 [2] 05 b8 }

  condition:
    any of them
}