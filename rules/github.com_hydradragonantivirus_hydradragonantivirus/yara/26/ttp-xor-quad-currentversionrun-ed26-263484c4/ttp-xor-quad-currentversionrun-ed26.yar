rule TTP_XOR_QUAD_CurrentVersionRun_ed26 {
  strings:
    $key_ed26 = { be 49 [2] 9a 47 [2] b1 6b [2] 9f 49 [2] 8b 52 [2] 84 48 [2] 9a 55 [2] 98 54 [2] 83 52 [2] 9f 55 [2] 83 7a }

  condition:
    any of them
}