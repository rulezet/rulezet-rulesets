rule TTP_XOR_QUAD_CurrentVersionRun_153e {
  strings:
    $key_153e = { 46 51 [2] 62 5f [2] 49 73 [2] 67 51 [2] 73 4a [2] 7c 50 [2] 62 4d [2] 60 4c [2] 7b 4a [2] 67 4d [2] 7b 62 }

  condition:
    any of them
}