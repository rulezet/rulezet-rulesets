rule TTP_XOR_QUAD_CurrentVersionRun_eb5d {
  strings:
    $key_eb5d = { b8 32 [2] 9c 3c [2] b7 10 [2] 99 32 [2] 8d 29 [2] 82 33 [2] 9c 2e [2] 9e 2f [2] 85 29 [2] 99 2e [2] 85 01 }

  condition:
    any of them
}