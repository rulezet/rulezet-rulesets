rule TTP_XOR_QUAD_CurrentVersionRun_eae8 {
  strings:
    $key_eae8 = { b9 87 [2] 9d 89 [2] b6 a5 [2] 98 87 [2] 8c 9c [2] 83 86 [2] 9d 9b [2] 9f 9a [2] 84 9c [2] 98 9b [2] 84 b4 }

  condition:
    any of them
}