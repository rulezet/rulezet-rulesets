rule TTP_XOR_QUAD_CurrentVersionRun_ed1c {
  strings:
    $key_ed1c = { be 73 [2] 9a 7d [2] b1 51 [2] 9f 73 [2] 8b 68 [2] 84 72 [2] 9a 6f [2] 98 6e [2] 83 68 [2] 9f 6f [2] 83 40 }

  condition:
    any of them
}