rule TTP_XOR_QUAD_CurrentVersionRun_ed2a {
  strings:
    $key_ed2a = { be 45 [2] 9a 4b [2] b1 67 [2] 9f 45 [2] 8b 5e [2] 84 44 [2] 9a 59 [2] 98 58 [2] 83 5e [2] 9f 59 [2] 83 76 }

  condition:
    any of them
}