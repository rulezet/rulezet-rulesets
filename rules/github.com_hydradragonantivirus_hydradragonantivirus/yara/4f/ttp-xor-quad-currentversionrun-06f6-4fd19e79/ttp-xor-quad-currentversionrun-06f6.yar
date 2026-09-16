rule TTP_XOR_QUAD_CurrentVersionRun_06f6 {
  strings:
    $key_06f6 = { 55 99 [2] 71 97 [2] 5a bb [2] 74 99 [2] 60 82 [2] 6f 98 [2] 71 85 [2] 73 84 [2] 68 82 [2] 74 85 [2] 68 aa }

  condition:
    any of them
}