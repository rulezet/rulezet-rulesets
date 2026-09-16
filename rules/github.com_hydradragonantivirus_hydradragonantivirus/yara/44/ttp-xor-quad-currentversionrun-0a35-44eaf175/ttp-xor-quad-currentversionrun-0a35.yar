rule TTP_XOR_QUAD_CurrentVersionRun_0a35 {
  strings:
    $key_0a35 = { 59 5a [2] 7d 54 [2] 56 78 [2] 78 5a [2] 6c 41 [2] 63 5b [2] 7d 46 [2] 7f 47 [2] 64 41 [2] 78 46 [2] 64 69 }

  condition:
    any of them
}