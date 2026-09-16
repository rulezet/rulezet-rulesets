rule TTP_XOR_QUAD_CurrentVersionRun_6be9 {
  strings:
    $key_6be9 = { 38 86 [2] 1c 88 [2] 37 a4 [2] 19 86 [2] 0d 9d [2] 02 87 [2] 1c 9a [2] 1e 9b [2] 05 9d [2] 19 9a [2] 05 b5 }

  condition:
    any of them
}