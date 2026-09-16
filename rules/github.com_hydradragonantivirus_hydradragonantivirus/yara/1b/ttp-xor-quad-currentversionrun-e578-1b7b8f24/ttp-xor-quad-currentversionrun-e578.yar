rule TTP_XOR_QUAD_CurrentVersionRun_e578 {
  strings:
    $key_e578 = { b6 17 [2] 92 19 [2] b9 35 [2] 97 17 [2] 83 0c [2] 8c 16 [2] 92 0b [2] 90 0a [2] 8b 0c [2] 97 0b [2] 8b 24 }

  condition:
    any of them
}