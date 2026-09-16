rule TTP_XOR_QUAD_CurrentVersionRun_78ee {
  strings:
    $key_78ee = { 2b 81 [2] 0f 8f [2] 24 a3 [2] 0a 81 [2] 1e 9a [2] 11 80 [2] 0f 9d [2] 0d 9c [2] 16 9a [2] 0a 9d [2] 16 b2 }

  condition:
    any of them
}