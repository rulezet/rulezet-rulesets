rule TTP_XOR_QUAD_CurrentVersionRun_161a {
  strings:
    $key_161a = { 45 75 [2] 61 7b [2] 4a 57 [2] 64 75 [2] 70 6e [2] 7f 74 [2] 61 69 [2] 63 68 [2] 78 6e [2] 64 69 [2] 78 46 }

  condition:
    any of them
}