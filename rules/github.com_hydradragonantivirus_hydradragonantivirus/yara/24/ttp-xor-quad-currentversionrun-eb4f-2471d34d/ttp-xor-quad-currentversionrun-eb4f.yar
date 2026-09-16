rule TTP_XOR_QUAD_CurrentVersionRun_eb4f {
  strings:
    $key_eb4f = { b8 20 [2] 9c 2e [2] b7 02 [2] 99 20 [2] 8d 3b [2] 82 21 [2] 9c 3c [2] 9e 3d [2] 85 3b [2] 99 3c [2] 85 13 }

  condition:
    any of them
}