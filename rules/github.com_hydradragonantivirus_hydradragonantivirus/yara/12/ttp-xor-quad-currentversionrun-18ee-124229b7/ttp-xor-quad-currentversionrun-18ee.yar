rule TTP_XOR_QUAD_CurrentVersionRun_18ee {
  strings:
    $key_18ee = { 4b 81 [2] 6f 8f [2] 44 a3 [2] 6a 81 [2] 7e 9a [2] 71 80 [2] 6f 9d [2] 6d 9c [2] 76 9a [2] 6a 9d [2] 76 b2 }

  condition:
    any of them
}