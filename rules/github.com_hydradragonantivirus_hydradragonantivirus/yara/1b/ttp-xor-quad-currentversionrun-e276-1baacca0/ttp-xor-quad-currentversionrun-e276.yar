rule TTP_XOR_QUAD_CurrentVersionRun_e276 {
  strings:
    $key_e276 = { b1 19 [2] 95 17 [2] be 3b [2] 90 19 [2] 84 02 [2] 8b 18 [2] 95 05 [2] 97 04 [2] 8c 02 [2] 90 05 [2] 8c 2a }

  condition:
    any of them
}