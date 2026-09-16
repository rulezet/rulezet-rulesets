rule TTP_XOR_QUAD_CurrentVersionRun_1b29 {
  strings:
    $key_1b29 = { 48 46 [2] 6c 48 [2] 47 64 [2] 69 46 [2] 7d 5d [2] 72 47 [2] 6c 5a [2] 6e 5b [2] 75 5d [2] 69 5a [2] 75 75 }

  condition:
    any of them
}