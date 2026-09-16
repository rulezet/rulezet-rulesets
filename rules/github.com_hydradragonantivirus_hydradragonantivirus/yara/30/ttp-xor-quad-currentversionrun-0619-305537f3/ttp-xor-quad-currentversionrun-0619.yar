rule TTP_XOR_QUAD_CurrentVersionRun_0619 {
  strings:
    $key_0619 = { 55 76 [2] 71 78 [2] 5a 54 [2] 74 76 [2] 60 6d [2] 6f 77 [2] 71 6a [2] 73 6b [2] 68 6d [2] 74 6a [2] 68 45 }

  condition:
    any of them
}