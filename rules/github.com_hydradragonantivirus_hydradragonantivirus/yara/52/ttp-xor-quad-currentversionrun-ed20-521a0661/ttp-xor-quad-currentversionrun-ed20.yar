rule TTP_XOR_QUAD_CurrentVersionRun_ed20 {
  strings:
    $key_ed20 = { be 4f [2] 9a 41 [2] b1 6d [2] 9f 4f [2] 8b 54 [2] 84 4e [2] 9a 53 [2] 98 52 [2] 83 54 [2] 9f 53 [2] 83 7c }

  condition:
    any of them
}