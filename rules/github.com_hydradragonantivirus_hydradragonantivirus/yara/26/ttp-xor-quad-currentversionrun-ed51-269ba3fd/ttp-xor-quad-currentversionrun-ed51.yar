rule TTP_XOR_QUAD_CurrentVersionRun_ed51 {
  strings:
    $key_ed51 = { be 3e [2] 9a 30 [2] b1 1c [2] 9f 3e [2] 8b 25 [2] 84 3f [2] 9a 22 [2] 98 23 [2] 83 25 [2] 9f 22 [2] 83 0d }

  condition:
    any of them
}