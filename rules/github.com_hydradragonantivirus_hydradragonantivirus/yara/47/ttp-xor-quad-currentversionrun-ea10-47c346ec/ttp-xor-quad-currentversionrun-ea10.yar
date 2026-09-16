rule TTP_XOR_QUAD_CurrentVersionRun_ea10 {
  strings:
    $key_ea10 = { b9 7f [2] 9d 71 [2] b6 5d [2] 98 7f [2] 8c 64 [2] 83 7e [2] 9d 63 [2] 9f 62 [2] 84 64 [2] 98 63 [2] 84 4c }

  condition:
    any of them
}