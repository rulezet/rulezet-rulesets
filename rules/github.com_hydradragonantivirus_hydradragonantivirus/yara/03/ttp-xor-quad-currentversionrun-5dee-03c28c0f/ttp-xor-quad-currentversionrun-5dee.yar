rule TTP_XOR_QUAD_CurrentVersionRun_5dee {
  strings:
    $key_5dee = { 0e 81 [2] 2a 8f [2] 01 a3 [2] 2f 81 [2] 3b 9a [2] 34 80 [2] 2a 9d [2] 28 9c [2] 33 9a [2] 2f 9d [2] 33 b2 }

  condition:
    any of them
}