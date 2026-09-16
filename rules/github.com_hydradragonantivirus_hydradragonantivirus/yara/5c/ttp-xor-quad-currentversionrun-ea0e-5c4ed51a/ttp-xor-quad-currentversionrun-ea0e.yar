rule TTP_XOR_QUAD_CurrentVersionRun_ea0e {
  strings:
    $key_ea0e = { b9 61 [2] 9d 6f [2] b6 43 [2] 98 61 [2] 8c 7a [2] 83 60 [2] 9d 7d [2] 9f 7c [2] 84 7a [2] 98 7d [2] 84 52 }

  condition:
    any of them
}