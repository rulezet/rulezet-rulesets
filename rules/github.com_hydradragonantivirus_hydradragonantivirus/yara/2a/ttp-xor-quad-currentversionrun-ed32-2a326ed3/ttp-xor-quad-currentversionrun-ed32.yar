rule TTP_XOR_QUAD_CurrentVersionRun_ed32 {
  strings:
    $key_ed32 = { be 5d [2] 9a 53 [2] b1 7f [2] 9f 5d [2] 8b 46 [2] 84 5c [2] 9a 41 [2] 98 40 [2] 83 46 [2] 9f 41 [2] 83 6e }

  condition:
    any of them
}