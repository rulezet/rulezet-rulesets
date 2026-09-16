rule TTP_XOR_QUAD_CurrentVersionRun_3f3e {
  strings:
    $key_3f3e = { 6c 51 [2] 48 5f [2] 63 73 [2] 4d 51 [2] 59 4a [2] 56 50 [2] 48 4d [2] 4a 4c [2] 51 4a [2] 4d 4d [2] 51 62 }

  condition:
    any of them
}