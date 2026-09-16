rule TTP_XOR_QUAD_CurrentVersionRun_496e {
  strings:
    $key_496e = { 1a 01 [2] 3e 0f [2] 15 23 [2] 3b 01 [2] 2f 1a [2] 20 00 [2] 3e 1d [2] 3c 1c [2] 27 1a [2] 3b 1d [2] 27 32 }

  condition:
    any of them
}