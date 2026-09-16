rule TTP_XOR_QUAD_CurrentVersionRun_0f1a {
  strings:
    $key_0f1a = { 5c 75 [2] 78 7b [2] 53 57 [2] 7d 75 [2] 69 6e [2] 66 74 [2] 78 69 [2] 7a 68 [2] 61 6e [2] 7d 69 [2] 61 46 }

  condition:
    any of them
}