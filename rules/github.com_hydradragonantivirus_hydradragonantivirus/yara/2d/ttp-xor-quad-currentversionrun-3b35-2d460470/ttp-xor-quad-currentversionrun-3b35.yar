rule TTP_XOR_QUAD_CurrentVersionRun_3b35 {
  strings:
    $key_3b35 = { 68 5a [2] 4c 54 [2] 67 78 [2] 49 5a [2] 5d 41 [2] 52 5b [2] 4c 46 [2] 4e 47 [2] 55 41 [2] 49 46 [2] 55 69 }

  condition:
    any of them
}