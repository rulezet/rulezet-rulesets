rule TTP_XOR_QUAD_CurrentVersionRun_124e {
  strings:
    $key_124e = { 41 21 [2] 65 2f [2] 4e 03 [2] 60 21 [2] 74 3a [2] 7b 20 [2] 65 3d [2] 67 3c [2] 7c 3a [2] 60 3d [2] 7c 12 }

  condition:
    any of them
}