rule TTP_XOR_QUAD_CurrentVersionRun_3725 {
  strings:
    $key_3725 = { 64 4a [2] 40 44 [2] 6b 68 [2] 45 4a [2] 51 51 [2] 5e 4b [2] 40 56 [2] 42 57 [2] 59 51 [2] 45 56 [2] 59 79 }

  condition:
    any of them
}