rule TTP_XOR_QUAD_CurrentVersionRun_7e3e {
  strings:
    $key_7e3e = { 2d 51 [2] 09 5f [2] 22 73 [2] 0c 51 [2] 18 4a [2] 17 50 [2] 09 4d [2] 0b 4c [2] 10 4a [2] 0c 4d [2] 10 62 }

  condition:
    any of them
}