rule TTP_XOR_QUAD_CurrentVersionRun_ed12 {
  strings:
    $key_ed12 = { be 7d [2] 9a 73 [2] b1 5f [2] 9f 7d [2] 8b 66 [2] 84 7c [2] 9a 61 [2] 98 60 [2] 83 66 [2] 9f 61 [2] 83 4e }

  condition:
    any of them
}