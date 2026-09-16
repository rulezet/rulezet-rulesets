rule TTP_XOR_QUAD_CurrentVersionRun_ea0a {
  strings:
    $key_ea0a = { b9 65 [2] 9d 6b [2] b6 47 [2] 98 65 [2] 8c 7e [2] 83 64 [2] 9d 79 [2] 9f 78 [2] 84 7e [2] 98 79 [2] 84 56 }

  condition:
    any of them
}