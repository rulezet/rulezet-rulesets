rule TTP_XOR_QUAD_CurrentVersionRun_0d35 {
  strings:
    $key_0d35 = { 5e 5a [2] 7a 54 [2] 51 78 [2] 7f 5a [2] 6b 41 [2] 64 5b [2] 7a 46 [2] 78 47 [2] 63 41 [2] 7f 46 [2] 63 69 }

  condition:
    any of them
}