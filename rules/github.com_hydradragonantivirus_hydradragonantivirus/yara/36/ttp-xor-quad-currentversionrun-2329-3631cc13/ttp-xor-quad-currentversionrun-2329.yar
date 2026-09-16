rule TTP_XOR_QUAD_CurrentVersionRun_2329 {
  strings:
    $key_2329 = { 70 46 [2] 54 48 [2] 7f 64 [2] 51 46 [2] 45 5d [2] 4a 47 [2] 54 5a [2] 56 5b [2] 4d 5d [2] 51 5a [2] 4d 75 }

  condition:
    any of them
}