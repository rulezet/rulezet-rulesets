rule TTP_XOR_QUAD_CurrentVersionRun_6dee {
  strings:
    $key_6dee = { 3e 81 [2] 1a 8f [2] 31 a3 [2] 1f 81 [2] 0b 9a [2] 04 80 [2] 1a 9d [2] 18 9c [2] 03 9a [2] 1f 9d [2] 03 b2 }

  condition:
    any of them
}