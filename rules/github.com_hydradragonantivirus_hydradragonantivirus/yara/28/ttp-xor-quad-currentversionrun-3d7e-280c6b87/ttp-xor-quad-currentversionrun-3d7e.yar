rule TTP_XOR_QUAD_CurrentVersionRun_3d7e {
  strings:
    $key_3d7e = { 6e 11 [2] 4a 1f [2] 61 33 [2] 4f 11 [2] 5b 0a [2] 54 10 [2] 4a 0d [2] 48 0c [2] 53 0a [2] 4f 0d [2] 53 22 }

  condition:
    any of them
}