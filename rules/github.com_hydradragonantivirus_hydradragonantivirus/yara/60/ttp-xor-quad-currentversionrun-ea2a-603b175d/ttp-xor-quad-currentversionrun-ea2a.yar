rule TTP_XOR_QUAD_CurrentVersionRun_ea2a {
  strings:
    $key_ea2a = { b9 45 [2] 9d 4b [2] b6 67 [2] 98 45 [2] 8c 5e [2] 83 44 [2] 9d 59 [2] 9f 58 [2] 84 5e [2] 98 59 [2] 84 76 }

  condition:
    any of them
}