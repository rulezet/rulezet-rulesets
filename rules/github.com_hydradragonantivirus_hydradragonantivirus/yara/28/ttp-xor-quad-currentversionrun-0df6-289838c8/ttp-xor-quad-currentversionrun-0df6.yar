rule TTP_XOR_QUAD_CurrentVersionRun_0df6 {
  strings:
    $key_0df6 = { 5e 99 [2] 7a 97 [2] 51 bb [2] 7f 99 [2] 6b 82 [2] 64 98 [2] 7a 85 [2] 78 84 [2] 63 82 [2] 7f 85 [2] 63 aa }

  condition:
    any of them
}