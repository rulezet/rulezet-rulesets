rule TTP_XOR_QUAD_CurrentVersionRun_eb01 {
  strings:
    $key_eb01 = { b8 6e [2] 9c 60 [2] b7 4c [2] 99 6e [2] 8d 75 [2] 82 6f [2] 9c 72 [2] 9e 73 [2] 85 75 [2] 99 72 [2] 85 5d }

  condition:
    any of them
}