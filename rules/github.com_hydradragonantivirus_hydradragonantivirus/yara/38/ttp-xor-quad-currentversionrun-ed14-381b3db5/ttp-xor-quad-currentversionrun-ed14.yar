rule TTP_XOR_QUAD_CurrentVersionRun_ed14 {
  strings:
    $key_ed14 = { be 7b [2] 9a 75 [2] b1 59 [2] 9f 7b [2] 8b 60 [2] 84 7a [2] 9a 67 [2] 98 66 [2] 83 60 [2] 9f 67 [2] 83 48 }

  condition:
    any of them
}