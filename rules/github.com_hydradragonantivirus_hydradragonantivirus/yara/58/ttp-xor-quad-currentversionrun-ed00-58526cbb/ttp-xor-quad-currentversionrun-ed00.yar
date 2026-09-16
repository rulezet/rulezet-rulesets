rule TTP_XOR_QUAD_CurrentVersionRun_ed00 {
  strings:
    $key_ed00 = { be 6f [2] 9a 61 [2] b1 4d [2] 9f 6f [2] 8b 74 [2] 84 6e [2] 9a 73 [2] 98 72 [2] 83 74 [2] 9f 73 [2] 83 5c }

  condition:
    any of them
}