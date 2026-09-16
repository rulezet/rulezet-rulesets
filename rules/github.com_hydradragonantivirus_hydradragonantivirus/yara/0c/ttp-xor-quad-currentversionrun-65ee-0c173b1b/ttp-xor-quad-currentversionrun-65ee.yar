rule TTP_XOR_QUAD_CurrentVersionRun_65ee {
  strings:
    $key_65ee = { 36 81 [2] 12 8f [2] 39 a3 [2] 17 81 [2] 03 9a [2] 0c 80 [2] 12 9d [2] 10 9c [2] 0b 9a [2] 17 9d [2] 0b b2 }

  condition:
    any of them
}