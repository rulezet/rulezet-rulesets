rule TTP_XOR_QUAD_CurrentVersionRun_112b {
  strings:
    $key_112b = { 42 44 [2] 66 4a [2] 4d 66 [2] 63 44 [2] 77 5f [2] 78 45 [2] 66 58 [2] 64 59 [2] 7f 5f [2] 63 58 [2] 7f 77 }

  condition:
    any of them
}