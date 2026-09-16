rule TTP_XOR_QUAD_CurrentVersionRun_1729 {
  strings:
    $key_1729 = { 44 46 [2] 60 48 [2] 4b 64 [2] 65 46 [2] 71 5d [2] 7e 47 [2] 60 5a [2] 62 5b [2] 79 5d [2] 65 5a [2] 79 75 }

  condition:
    any of them
}