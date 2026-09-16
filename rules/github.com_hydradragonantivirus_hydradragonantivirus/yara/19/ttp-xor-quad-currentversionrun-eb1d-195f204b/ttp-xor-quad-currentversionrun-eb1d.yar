rule TTP_XOR_QUAD_CurrentVersionRun_eb1d {
  strings:
    $key_eb1d = { b8 72 [2] 9c 7c [2] b7 50 [2] 99 72 [2] 8d 69 [2] 82 73 [2] 9c 6e [2] 9e 6f [2] 85 69 [2] 99 6e [2] 85 41 }

  condition:
    any of them
}