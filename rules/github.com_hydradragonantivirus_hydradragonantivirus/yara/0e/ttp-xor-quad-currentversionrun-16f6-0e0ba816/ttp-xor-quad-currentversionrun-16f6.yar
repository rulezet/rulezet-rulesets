rule TTP_XOR_QUAD_CurrentVersionRun_16f6 {
  strings:
    $key_16f6 = { 45 99 [2] 61 97 [2] 4a bb [2] 64 99 [2] 70 82 [2] 7f 98 [2] 61 85 [2] 63 84 [2] 78 82 [2] 64 85 [2] 78 aa }

  condition:
    any of them
}