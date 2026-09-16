rule TTP_XOR_QUAD_CurrentVersionRun_ed10 {
  strings:
    $key_ed10 = { be 7f [2] 9a 71 [2] b1 5d [2] 9f 7f [2] 8b 64 [2] 84 7e [2] 9a 63 [2] 98 62 [2] 83 64 [2] 9f 63 [2] 83 4c }

  condition:
    any of them
}