rule TTP_XOR_QUAD_CurrentVersionRun_eb7c {
  strings:
    $key_eb7c = { b8 13 [2] 9c 1d [2] b7 31 [2] 99 13 [2] 8d 08 [2] 82 12 [2] 9c 0f [2] 9e 0e [2] 85 08 [2] 99 0f [2] 85 20 }

  condition:
    any of them
}