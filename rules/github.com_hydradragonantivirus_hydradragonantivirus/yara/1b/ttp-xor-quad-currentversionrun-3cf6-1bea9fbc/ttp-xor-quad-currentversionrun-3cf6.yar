rule TTP_XOR_QUAD_CurrentVersionRun_3cf6 {
  strings:
    $key_3cf6 = { 6f 99 [2] 4b 97 [2] 60 bb [2] 4e 99 [2] 5a 82 [2] 55 98 [2] 4b 85 [2] 49 84 [2] 52 82 [2] 4e 85 [2] 52 aa }

  condition:
    any of them
}