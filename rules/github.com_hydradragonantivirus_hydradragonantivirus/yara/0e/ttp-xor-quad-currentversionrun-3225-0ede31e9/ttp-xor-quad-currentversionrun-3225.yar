rule TTP_XOR_QUAD_CurrentVersionRun_3225 {
  strings:
    $key_3225 = { 61 4a [2] 45 44 [2] 6e 68 [2] 40 4a [2] 54 51 [2] 5b 4b [2] 45 56 [2] 47 57 [2] 5c 51 [2] 40 56 [2] 5c 79 }

  condition:
    any of them
}