rule TTP_XOR_QUAD_CurrentVersionRun_2738 {
  strings:
    $key_2738 = { 74 57 [2] 50 59 [2] 7b 75 [2] 55 57 [2] 41 4c [2] 4e 56 [2] 50 4b [2] 52 4a [2] 49 4c [2] 55 4b [2] 49 64 }

  condition:
    any of them
}