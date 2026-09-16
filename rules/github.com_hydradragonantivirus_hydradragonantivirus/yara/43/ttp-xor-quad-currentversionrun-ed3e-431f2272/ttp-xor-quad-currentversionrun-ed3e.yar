rule TTP_XOR_QUAD_CurrentVersionRun_ed3e {
  strings:
    $key_ed3e = { be 51 [2] 9a 5f [2] b1 73 [2] 9f 51 [2] 8b 4a [2] 84 50 [2] 9a 4d [2] 98 4c [2] 83 4a [2] 9f 4d [2] 83 62 }

  condition:
    any of them
}