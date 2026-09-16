rule TTP_XOR_QUAD_CurrentVersionRun_f61e {
  strings:
    $key_f61e = { a5 71 [2] 81 7f [2] aa 53 [2] 84 71 [2] 90 6a [2] 9f 70 [2] 81 6d [2] 83 6c [2] 98 6a [2] 84 6d [2] 98 42 }

  condition:
    any of them
}