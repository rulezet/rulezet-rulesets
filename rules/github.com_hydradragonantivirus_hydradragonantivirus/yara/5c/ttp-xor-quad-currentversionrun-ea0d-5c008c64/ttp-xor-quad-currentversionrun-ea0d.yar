rule TTP_XOR_QUAD_CurrentVersionRun_ea0d {
  strings:
    $key_ea0d = { b9 62 [2] 9d 6c [2] b6 40 [2] 98 62 [2] 8c 79 [2] 83 63 [2] 9d 7e [2] 9f 7f [2] 84 79 [2] 98 7e [2] 84 51 }

  condition:
    any of them
}