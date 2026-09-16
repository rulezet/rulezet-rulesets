rule TTP_XOR_QUAD_CurrentVersionRun_15ee {
  strings:
    $key_15ee = { 46 81 [2] 62 8f [2] 49 a3 [2] 67 81 [2] 73 9a [2] 7c 80 [2] 62 9d [2] 60 9c [2] 7b 9a [2] 67 9d [2] 7b b2 }

  condition:
    any of them
}