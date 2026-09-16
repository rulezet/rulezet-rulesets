rule TTP_XOR_QUAD_CurrentVersionRun_edee {
  strings:
    $key_edee = { be 81 [2] 9a 8f [2] b1 a3 [2] 9f 81 [2] 8b 9a [2] 84 80 [2] 9a 9d [2] 98 9c [2] 83 9a [2] 9f 9d [2] 83 b2 }

  condition:
    any of them
}