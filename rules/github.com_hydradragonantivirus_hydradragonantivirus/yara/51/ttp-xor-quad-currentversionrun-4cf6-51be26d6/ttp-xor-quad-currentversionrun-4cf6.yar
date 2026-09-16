rule TTP_XOR_QUAD_CurrentVersionRun_4cf6 {
  strings:
    $key_4cf6 = { 1f 99 [2] 3b 97 [2] 10 bb [2] 3e 99 [2] 2a 82 [2] 25 98 [2] 3b 85 [2] 39 84 [2] 22 82 [2] 3e 85 [2] 22 aa }

  condition:
    any of them
}