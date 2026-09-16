rule TTP_XOR_QUAD_CurrentVersionRun_6a3e {
  strings:
    $key_6a3e = { 39 51 [2] 1d 5f [2] 36 73 [2] 18 51 [2] 0c 4a [2] 03 50 [2] 1d 4d [2] 1f 4c [2] 04 4a [2] 18 4d [2] 04 62 }

  condition:
    any of them
}