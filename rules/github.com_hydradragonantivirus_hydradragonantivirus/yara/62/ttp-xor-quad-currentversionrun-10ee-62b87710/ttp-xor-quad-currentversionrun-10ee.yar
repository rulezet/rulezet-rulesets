rule TTP_XOR_QUAD_CurrentVersionRun_10ee {
  strings:
    $key_10ee = { 43 81 [2] 67 8f [2] 4c a3 [2] 62 81 [2] 76 9a [2] 79 80 [2] 67 9d [2] 65 9c [2] 7e 9a [2] 62 9d [2] 7e b2 }

  condition:
    any of them
}