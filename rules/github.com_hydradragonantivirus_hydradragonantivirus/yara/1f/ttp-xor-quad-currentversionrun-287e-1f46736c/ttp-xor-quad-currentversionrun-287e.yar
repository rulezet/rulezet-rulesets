rule TTP_XOR_QUAD_CurrentVersionRun_287e {
  strings:
    $key_287e = { 7b 11 [2] 5f 1f [2] 74 33 [2] 5a 11 [2] 4e 0a [2] 41 10 [2] 5f 0d [2] 5d 0c [2] 46 0a [2] 5a 0d [2] 46 22 }

  condition:
    any of them
}