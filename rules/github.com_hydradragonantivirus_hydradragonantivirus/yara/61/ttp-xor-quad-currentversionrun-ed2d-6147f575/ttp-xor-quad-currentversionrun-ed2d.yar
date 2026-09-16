rule TTP_XOR_QUAD_CurrentVersionRun_ed2d {
  strings:
    $key_ed2d = { be 42 [2] 9a 4c [2] b1 60 [2] 9f 42 [2] 8b 59 [2] 84 43 [2] 9a 5e [2] 98 5f [2] 83 59 [2] 9f 5e [2] 83 71 }

  condition:
    any of them
}