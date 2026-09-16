rule TTP_XOR_QUAD_CurrentVersionRun_eb21 {
  strings:
    $key_eb21 = { b8 4e [2] 9c 40 [2] b7 6c [2] 99 4e [2] 8d 55 [2] 82 4f [2] 9c 52 [2] 9e 53 [2] 85 55 [2] 99 52 [2] 85 7d }

  condition:
    any of them
}