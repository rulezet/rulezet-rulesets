rule TTP_XOR_QUAD_CurrentVersionRun_edf6 {
  strings:
    $key_edf6 = { be 99 [2] 9a 97 [2] b1 bb [2] 9f 99 [2] 8b 82 [2] 84 98 [2] 9a 85 [2] 98 84 [2] 83 82 [2] 9f 85 [2] 83 aa }

  condition:
    any of them
}