rule TTP_XOR_QUAD_CurrentVersionRun_ed3b {
  strings:
    $key_ed3b = { be 54 [2] 9a 5a [2] b1 76 [2] 9f 54 [2] 8b 4f [2] 84 55 [2] 9a 48 [2] 98 49 [2] 83 4f [2] 9f 48 [2] 83 67 }

  condition:
    any of them
}