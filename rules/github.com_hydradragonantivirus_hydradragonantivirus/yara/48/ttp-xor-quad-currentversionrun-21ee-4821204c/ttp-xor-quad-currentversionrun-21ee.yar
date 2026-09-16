rule TTP_XOR_QUAD_CurrentVersionRun_21ee {
  strings:
    $key_21ee = { 72 81 [2] 56 8f [2] 7d a3 [2] 53 81 [2] 47 9a [2] 48 80 [2] 56 9d [2] 54 9c [2] 4f 9a [2] 53 9d [2] 4f b2 }

  condition:
    any of them
}