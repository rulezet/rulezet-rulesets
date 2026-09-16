rule TTP_XOR_QUAD_CurrentVersionRun_1c38 {
  strings:
    $key_1c38 = { 4f 57 [2] 6b 59 [2] 40 75 [2] 6e 57 [2] 7a 4c [2] 75 56 [2] 6b 4b [2] 69 4a [2] 72 4c [2] 6e 4b [2] 72 64 }

  condition:
    any of them
}