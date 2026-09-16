rule TTP_XOR_QUAD_CurrentVersionRun_0ee8 {
  strings:
    $key_0ee8 = { 5d 87 [2] 79 89 [2] 52 a5 [2] 7c 87 [2] 68 9c [2] 67 86 [2] 79 9b [2] 7b 9a [2] 60 9c [2] 7c 9b [2] 60 b4 }

  condition:
    any of them
}