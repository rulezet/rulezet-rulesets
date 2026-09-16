rule TTP_XOR_QUAD_CurrentVersionRun_0128 {
  strings:
    $key_0128 = { 52 47 [2] 76 49 [2] 5d 65 [2] 73 47 [2] 67 5c [2] 68 46 [2] 76 5b [2] 74 5a [2] 6f 5c [2] 73 5b [2] 6f 74 }

  condition:
    any of them
}