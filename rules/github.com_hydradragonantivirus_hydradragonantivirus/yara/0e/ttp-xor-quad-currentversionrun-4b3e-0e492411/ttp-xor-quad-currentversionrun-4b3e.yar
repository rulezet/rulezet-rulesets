rule TTP_XOR_QUAD_CurrentVersionRun_4b3e {
  strings:
    $key_4b3e = { 18 51 [2] 3c 5f [2] 17 73 [2] 39 51 [2] 2d 4a [2] 22 50 [2] 3c 4d [2] 3e 4c [2] 25 4a [2] 39 4d [2] 25 62 }

  condition:
    any of them
}