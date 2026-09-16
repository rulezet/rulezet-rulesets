rule TTP_XOR_QUAD_CurrentVersionRun_281e {
  strings:
    $key_281e = { 7b 71 [2] 5f 7f [2] 74 53 [2] 5a 71 [2] 4e 6a [2] 41 70 [2] 5f 6d [2] 5d 6c [2] 46 6a [2] 5a 6d [2] 46 42 }

  condition:
    any of them
}