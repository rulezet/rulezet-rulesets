rule TTP_XOR_QUAD_CurrentVersionRun_eb2e {
  strings:
    $key_eb2e = { b8 41 [2] 9c 4f [2] b7 63 [2] 99 41 [2] 8d 5a [2] 82 40 [2] 9c 5d [2] 9e 5c [2] 85 5a [2] 99 5d [2] 85 72 }

  condition:
    any of them
}