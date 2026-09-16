rule TTP_XOR_QUAD_CurrentVersionRun_0f62 {
  strings:
    $key_0f62 = { 5c 0d [2] 78 03 [2] 53 2f [2] 7d 0d [2] 69 16 [2] 66 0c [2] 78 11 [2] 7a 10 [2] 61 16 [2] 7d 11 [2] 61 3e }

  condition:
    any of them
}