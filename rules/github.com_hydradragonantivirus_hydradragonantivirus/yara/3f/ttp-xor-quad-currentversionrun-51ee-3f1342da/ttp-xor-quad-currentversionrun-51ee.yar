rule TTP_XOR_QUAD_CurrentVersionRun_51ee {
  strings:
    $key_51ee = { 02 81 [2] 26 8f [2] 0d a3 [2] 23 81 [2] 37 9a [2] 38 80 [2] 26 9d [2] 24 9c [2] 3f 9a [2] 23 9d [2] 3f b2 }

  condition:
    any of them
}