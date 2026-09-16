rule TTP_XOR_QUAD_CurrentVersionRun_5778 {
  strings:
    $key_5778 = { 04 17 [2] 20 19 [2] 0b 35 [2] 25 17 [2] 31 0c [2] 3e 16 [2] 20 0b [2] 22 0a [2] 39 0c [2] 25 0b [2] 39 24 }

  condition:
    any of them
}