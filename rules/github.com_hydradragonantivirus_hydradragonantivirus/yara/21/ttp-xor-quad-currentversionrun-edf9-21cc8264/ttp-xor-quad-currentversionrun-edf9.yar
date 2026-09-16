rule TTP_XOR_QUAD_CurrentVersionRun_edf9 {
  strings:
    $key_edf9 = { be 96 [2] 9a 98 [2] b1 b4 [2] 9f 96 [2] 8b 8d [2] 84 97 [2] 9a 8a [2] 98 8b [2] 83 8d [2] 9f 8a [2] 83 a5 }

  condition:
    any of them
}