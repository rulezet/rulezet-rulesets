rule TTP_XOR_QUAD_CurrentVersionRun_3a3e {
  strings:
    $key_3a3e = { 69 51 [2] 4d 5f [2] 66 73 [2] 48 51 [2] 5c 4a [2] 53 50 [2] 4d 4d [2] 4f 4c [2] 54 4a [2] 48 4d [2] 54 62 }

  condition:
    any of them
}