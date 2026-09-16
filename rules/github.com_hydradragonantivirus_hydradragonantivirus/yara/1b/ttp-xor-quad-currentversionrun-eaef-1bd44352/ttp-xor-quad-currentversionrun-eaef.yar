rule TTP_XOR_QUAD_CurrentVersionRun_eaef {
  strings:
    $key_eaef = { b9 80 [2] 9d 8e [2] b6 a2 [2] 98 80 [2] 8c 9b [2] 83 81 [2] 9d 9c [2] 9f 9d [2] 84 9b [2] 98 9c [2] 84 b3 }

  condition:
    any of them
}