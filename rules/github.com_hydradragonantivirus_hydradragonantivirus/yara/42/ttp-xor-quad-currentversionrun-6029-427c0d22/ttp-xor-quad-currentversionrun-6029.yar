rule TTP_XOR_QUAD_CurrentVersionRun_6029 {
  strings:
    $key_6029 = { 33 46 [2] 17 48 [2] 3c 64 [2] 12 46 [2] 06 5d [2] 09 47 [2] 17 5a [2] 15 5b [2] 0e 5d [2] 12 5a [2] 0e 75 }

  condition:
    any of them
}