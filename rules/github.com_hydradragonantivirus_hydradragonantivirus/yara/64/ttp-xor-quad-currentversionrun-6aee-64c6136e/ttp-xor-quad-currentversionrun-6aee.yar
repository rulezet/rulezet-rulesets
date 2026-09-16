rule TTP_XOR_QUAD_CurrentVersionRun_6aee {
  strings:
    $key_6aee = { 39 81 [2] 1d 8f [2] 36 a3 [2] 18 81 [2] 0c 9a [2] 03 80 [2] 1d 9d [2] 1f 9c [2] 04 9a [2] 18 9d [2] 04 b2 }

  condition:
    any of them
}