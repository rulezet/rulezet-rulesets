rule TTP_XOR_QUAD_CurrentVersionRun_3b3e {
  strings:
    $key_3b3e = { 68 51 [2] 4c 5f [2] 67 73 [2] 49 51 [2] 5d 4a [2] 52 50 [2] 4c 4d [2] 4e 4c [2] 55 4a [2] 49 4d [2] 55 62 }

  condition:
    any of them
}