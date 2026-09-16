rule TTP_XOR_QUAD_CurrentVersionRun_eb2d {
  strings:
    $key_eb2d = { b8 42 [2] 9c 4c [2] b7 60 [2] 99 42 [2] 8d 59 [2] 82 43 [2] 9c 5e [2] 9e 5f [2] 85 59 [2] 99 5e [2] 85 71 }

  condition:
    any of them
}