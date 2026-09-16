rule TTP_XOR_QUAD_CurrentVersionRun_ea2d {
  strings:
    $key_ea2d = { b9 42 [2] 9d 4c [2] b6 60 [2] 98 42 [2] 8c 59 [2] 83 43 [2] 9d 5e [2] 9f 5f [2] 84 59 [2] 98 5e [2] 84 71 }

  condition:
    any of them
}