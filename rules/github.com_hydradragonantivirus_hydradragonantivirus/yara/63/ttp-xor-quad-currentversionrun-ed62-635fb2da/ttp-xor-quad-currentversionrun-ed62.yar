rule TTP_XOR_QUAD_CurrentVersionRun_ed62 {
  strings:
    $key_ed62 = { be 0d [2] 9a 03 [2] b1 2f [2] 9f 0d [2] 8b 16 [2] 84 0c [2] 9a 11 [2] 98 10 [2] 83 16 [2] 9f 11 [2] 83 3e }

  condition:
    any of them
}