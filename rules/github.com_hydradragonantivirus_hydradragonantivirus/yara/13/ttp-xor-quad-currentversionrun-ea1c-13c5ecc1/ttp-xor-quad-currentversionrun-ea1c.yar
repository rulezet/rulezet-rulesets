rule TTP_XOR_QUAD_CurrentVersionRun_ea1c {
  strings:
    $key_ea1c = { b9 73 [2] 9d 7d [2] b6 51 [2] 98 73 [2] 8c 68 [2] 83 72 [2] 9d 6f [2] 9f 6e [2] 84 68 [2] 98 6f [2] 84 40 }

  condition:
    any of them
}