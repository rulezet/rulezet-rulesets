rule TTP_XOR_QUAD_CurrentVersionRun_ea0f {
  strings:
    $key_ea0f = { b9 60 [2] 9d 6e [2] b6 42 [2] 98 60 [2] 8c 7b [2] 83 61 [2] 9d 7c [2] 9f 7d [2] 84 7b [2] 98 7c [2] 84 53 }

  condition:
    any of them
}