rule TTP_XOR_QUAD_CurrentVersionRun_ed06 {
  strings:
    $key_ed06 = { be 69 [2] 9a 67 [2] b1 4b [2] 9f 69 [2] 8b 72 [2] 84 68 [2] 9a 75 [2] 98 74 [2] 83 72 [2] 9f 75 [2] 83 5a }

  condition:
    any of them
}