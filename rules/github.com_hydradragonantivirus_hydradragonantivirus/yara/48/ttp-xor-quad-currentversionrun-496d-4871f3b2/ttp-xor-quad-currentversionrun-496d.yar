rule TTP_XOR_QUAD_CurrentVersionRun_496d {
  strings:
    $key_496d = { 1a 02 [2] 3e 0c [2] 15 20 [2] 3b 02 [2] 2f 19 [2] 20 03 [2] 3e 1e [2] 3c 1f [2] 27 19 [2] 3b 1e [2] 27 31 }

  condition:
    any of them
}