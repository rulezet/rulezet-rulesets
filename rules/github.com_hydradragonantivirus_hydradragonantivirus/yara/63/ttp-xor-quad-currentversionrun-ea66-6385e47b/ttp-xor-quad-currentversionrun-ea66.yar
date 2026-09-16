rule TTP_XOR_QUAD_CurrentVersionRun_ea66 {
  strings:
    $key_ea66 = { b9 09 [2] 9d 07 [2] b6 2b [2] 98 09 [2] 8c 12 [2] 83 08 [2] 9d 15 [2] 9f 14 [2] 84 12 [2] 98 15 [2] 84 3a }

  condition:
    any of them
}