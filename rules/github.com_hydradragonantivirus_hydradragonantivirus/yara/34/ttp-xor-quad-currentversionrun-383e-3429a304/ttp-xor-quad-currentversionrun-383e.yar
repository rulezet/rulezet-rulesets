rule TTP_XOR_QUAD_CurrentVersionRun_383e {
  strings:
    $key_383e = { 6b 51 [2] 4f 5f [2] 64 73 [2] 4a 51 [2] 5e 4a [2] 51 50 [2] 4f 4d [2] 4d 4c [2] 56 4a [2] 4a 4d [2] 56 62 }

  condition:
    any of them
}