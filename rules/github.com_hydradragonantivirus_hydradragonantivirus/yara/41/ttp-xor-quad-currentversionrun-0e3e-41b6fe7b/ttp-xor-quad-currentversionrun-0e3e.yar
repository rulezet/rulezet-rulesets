rule TTP_XOR_QUAD_CurrentVersionRun_0e3e {
  strings:
    $key_0e3e = { 5d 51 [2] 79 5f [2] 52 73 [2] 7c 51 [2] 68 4a [2] 67 50 [2] 79 4d [2] 7b 4c [2] 60 4a [2] 7c 4d [2] 60 62 }

  condition:
    any of them
}