rule TTP_XOR_QUAD_CurrentVersionRun_ebef {
  strings:
    $key_ebef = { b8 80 [2] 9c 8e [2] b7 a2 [2] 99 80 [2] 8d 9b [2] 82 81 [2] 9c 9c [2] 9e 9d [2] 85 9b [2] 99 9c [2] 85 b3 }

  condition:
    any of them
}