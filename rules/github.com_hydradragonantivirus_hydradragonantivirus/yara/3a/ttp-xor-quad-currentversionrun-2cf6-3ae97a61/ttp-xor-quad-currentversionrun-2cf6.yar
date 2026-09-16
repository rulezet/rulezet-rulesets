rule TTP_XOR_QUAD_CurrentVersionRun_2cf6 {
  strings:
    $key_2cf6 = { 7f 99 [2] 5b 97 [2] 70 bb [2] 5e 99 [2] 4a 82 [2] 45 98 [2] 5b 85 [2] 59 84 [2] 42 82 [2] 5e 85 [2] 42 aa }

  condition:
    any of them
}