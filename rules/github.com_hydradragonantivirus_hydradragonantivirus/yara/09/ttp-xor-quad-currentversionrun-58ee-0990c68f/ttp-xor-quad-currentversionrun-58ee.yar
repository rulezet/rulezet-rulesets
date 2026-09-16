rule TTP_XOR_QUAD_CurrentVersionRun_58ee {
  strings:
    $key_58ee = { 0b 81 [2] 2f 8f [2] 04 a3 [2] 2a 81 [2] 3e 9a [2] 31 80 [2] 2f 9d [2] 2d 9c [2] 36 9a [2] 2a 9d [2] 36 b2 }

  condition:
    any of them
}