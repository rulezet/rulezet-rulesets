rule TTP_XOR_QUAD_CurrentVersionRun_3428 {
  strings:
    $key_3428 = { 67 47 [2] 43 49 [2] 68 65 [2] 46 47 [2] 52 5c [2] 5d 46 [2] 43 5b [2] 41 5a [2] 5a 5c [2] 46 5b [2] 5a 74 }

  condition:
    any of them
}