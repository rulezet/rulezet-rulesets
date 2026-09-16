rule TTP_XOR_QUAD_CurrentVersionRun_eded {
  strings:
    $key_eded = { be 82 [2] 9a 8c [2] b1 a0 [2] 9f 82 [2] 8b 99 [2] 84 83 [2] 9a 9e [2] 98 9f [2] 83 99 [2] 9f 9e [2] 83 b1 }

  condition:
    any of them
}