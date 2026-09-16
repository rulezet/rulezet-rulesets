rule TTP_XOR_QUAD_CurrentVersionRun_2328 {
  strings:
    $key_2328 = { 70 47 [2] 54 49 [2] 7f 65 [2] 51 47 [2] 45 5c [2] 4a 46 [2] 54 5b [2] 56 5a [2] 4d 5c [2] 51 5b [2] 4d 74 }

  condition:
    any of them
}