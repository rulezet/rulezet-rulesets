rule TTP_XOR_QUAD_CurrentVersionRun_3735 {
  strings:
    $key_3735 = { 64 5a [2] 40 54 [2] 6b 78 [2] 45 5a [2] 51 41 [2] 5e 5b [2] 40 46 [2] 42 47 [2] 59 41 [2] 45 46 [2] 59 69 }

  condition:
    any of them
}