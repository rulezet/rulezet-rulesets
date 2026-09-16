rule TTP_XOR_QUAD_CurrentVersionRun_3b29 {
  strings:
    $key_3b29 = { 68 46 [2] 4c 48 [2] 67 64 [2] 49 46 [2] 5d 5d [2] 52 47 [2] 4c 5a [2] 4e 5b [2] 55 5d [2] 49 5a [2] 55 75 }

  condition:
    any of them
}