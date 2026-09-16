rule TTP_XOR_QUAD_CurrentVersionRun_2729 {
  strings:
    $key_2729 = { 74 46 [2] 50 48 [2] 7b 64 [2] 55 46 [2] 41 5d [2] 4e 47 [2] 50 5a [2] 52 5b [2] 49 5d [2] 55 5a [2] 49 75 }

  condition:
    any of them
}