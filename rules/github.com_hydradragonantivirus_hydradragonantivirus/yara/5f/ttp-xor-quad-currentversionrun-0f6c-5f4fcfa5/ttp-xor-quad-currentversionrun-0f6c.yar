rule TTP_XOR_QUAD_CurrentVersionRun_0f6c {
  strings:
    $key_0f6c = { 5c 03 [2] 78 0d [2] 53 21 [2] 7d 03 [2] 69 18 [2] 66 02 [2] 78 1f [2] 7a 1e [2] 61 18 [2] 7d 1f [2] 61 30 }

  condition:
    any of them
}