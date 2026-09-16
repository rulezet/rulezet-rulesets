rule TTP_XOR_QUAD_CurrentVersionRun_2034 {
  strings:
    $key_2034 = { 73 5b [2] 57 55 [2] 7c 79 [2] 52 5b [2] 46 40 [2] 49 5a [2] 57 47 [2] 55 46 [2] 4e 40 [2] 52 47 [2] 4e 68 }

  condition:
    any of them
}