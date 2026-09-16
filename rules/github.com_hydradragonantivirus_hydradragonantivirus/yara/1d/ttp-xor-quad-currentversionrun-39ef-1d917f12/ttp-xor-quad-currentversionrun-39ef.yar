rule TTP_XOR_QUAD_CurrentVersionRun_39ef {
  strings:
    $key_39ef = { 6a 80 [2] 4e 8e [2] 65 a2 [2] 4b 80 [2] 5f 9b [2] 50 81 [2] 4e 9c [2] 4c 9d [2] 57 9b [2] 4b 9c [2] 57 b3 }

  condition:
    any of them
}