rule TTP_XOR_QUAD_CurrentVersionRun_0a3e {
  strings:
    $key_0a3e = { 59 51 [2] 7d 5f [2] 56 73 [2] 78 51 [2] 6c 4a [2] 63 50 [2] 7d 4d [2] 7f 4c [2] 64 4a [2] 78 4d [2] 64 62 }

  condition:
    any of them
}