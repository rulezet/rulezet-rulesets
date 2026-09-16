rule TTP_XOR_QUAD_CurrentVersionRun_5724 {
  strings:
    $key_5724 = { 04 4b [2] 20 45 [2] 0b 69 [2] 25 4b [2] 31 50 [2] 3e 4a [2] 20 57 [2] 22 56 [2] 39 50 [2] 25 57 [2] 39 78 }

  condition:
    any of them
}