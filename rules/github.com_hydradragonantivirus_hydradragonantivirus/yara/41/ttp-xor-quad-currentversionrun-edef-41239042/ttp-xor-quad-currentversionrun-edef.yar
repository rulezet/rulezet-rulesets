rule TTP_XOR_QUAD_CurrentVersionRun_edef {
  strings:
    $key_edef = { be 80 [2] 9a 8e [2] b1 a2 [2] 9f 80 [2] 8b 9b [2] 84 81 [2] 9a 9c [2] 98 9d [2] 83 9b [2] 9f 9c [2] 83 b3 }

  condition:
    any of them
}