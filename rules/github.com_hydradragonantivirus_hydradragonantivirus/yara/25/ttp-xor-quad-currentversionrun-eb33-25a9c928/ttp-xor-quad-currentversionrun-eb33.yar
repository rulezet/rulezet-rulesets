rule TTP_XOR_QUAD_CurrentVersionRun_eb33 {
  strings:
    $key_eb33 = { b8 5c [2] 9c 52 [2] b7 7e [2] 99 5c [2] 8d 47 [2] 82 5d [2] 9c 40 [2] 9e 41 [2] 85 47 [2] 99 40 [2] 85 6f }

  condition:
    any of them
}