rule TTP_XOR_QUAD_CurrentVersionRun_76f6 {
  strings:
    $key_76f6 = { 25 99 [2] 01 97 [2] 2a bb [2] 04 99 [2] 10 82 [2] 1f 98 [2] 01 85 [2] 03 84 [2] 18 82 [2] 04 85 [2] 18 aa }

  condition:
    any of them
}