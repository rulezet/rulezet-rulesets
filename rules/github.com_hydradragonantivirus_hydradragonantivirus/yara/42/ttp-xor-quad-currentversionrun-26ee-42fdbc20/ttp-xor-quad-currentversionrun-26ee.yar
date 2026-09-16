rule TTP_XOR_QUAD_CurrentVersionRun_26ee {
  strings:
    $key_26ee = { 75 81 [2] 51 8f [2] 7a a3 [2] 54 81 [2] 40 9a [2] 4f 80 [2] 51 9d [2] 53 9c [2] 48 9a [2] 54 9d [2] 48 b2 }

  condition:
    any of them
}