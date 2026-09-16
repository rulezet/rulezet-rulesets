rule TTP_XOR_QUAD_CurrentVersionRun_ea6d {
  strings:
    $key_ea6d = { b9 02 [2] 9d 0c [2] b6 20 [2] 98 02 [2] 8c 19 [2] 83 03 [2] 9d 1e [2] 9f 1f [2] 84 19 [2] 98 1e [2] 84 31 }

  condition:
    any of them
}