rule TTP_XOR_QUAD_CurrentVersionRun_ed30 {
  strings:
    $key_ed30 = { be 5f [2] 9a 51 [2] b1 7d [2] 9f 5f [2] 8b 44 [2] 84 5e [2] 9a 43 [2] 98 42 [2] 83 44 [2] 9f 43 [2] 83 6c }

  condition:
    any of them
}