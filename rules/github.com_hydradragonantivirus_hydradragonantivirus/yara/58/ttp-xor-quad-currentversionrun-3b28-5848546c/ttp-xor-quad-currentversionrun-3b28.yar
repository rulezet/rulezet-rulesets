rule TTP_XOR_QUAD_CurrentVersionRun_3b28 {
  strings:
    $key_3b28 = { 68 47 [2] 4c 49 [2] 67 65 [2] 49 47 [2] 5d 5c [2] 52 46 [2] 4c 5b [2] 4e 5a [2] 55 5c [2] 49 5b [2] 55 74 }

  condition:
    any of them
}