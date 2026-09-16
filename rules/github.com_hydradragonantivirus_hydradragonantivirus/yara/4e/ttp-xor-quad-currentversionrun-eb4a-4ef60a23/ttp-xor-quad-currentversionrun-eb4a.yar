rule TTP_XOR_QUAD_CurrentVersionRun_eb4a {
  strings:
    $key_eb4a = { b8 25 [2] 9c 2b [2] b7 07 [2] 99 25 [2] 8d 3e [2] 82 24 [2] 9c 39 [2] 9e 38 [2] 85 3e [2] 99 39 [2] 85 16 }

  condition:
    any of them
}