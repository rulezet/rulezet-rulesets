rule TTP_XOR_QUAD_CurrentVersionRun_2038 {
  strings:
    $key_2038 = { 73 57 [2] 57 59 [2] 7c 75 [2] 52 57 [2] 46 4c [2] 49 56 [2] 57 4b [2] 55 4a [2] 4e 4c [2] 52 4b [2] 4e 64 }

  condition:
    any of them
}