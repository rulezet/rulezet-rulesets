rule TTP_XOR_QUAD_CurrentVersionRun_201e {
  strings:
    $key_201e = { 73 71 [2] 57 7f [2] 7c 53 [2] 52 71 [2] 46 6a [2] 49 70 [2] 57 6d [2] 55 6c [2] 4e 6a [2] 52 6d [2] 4e 42 }

  condition:
    any of them
}