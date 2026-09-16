rule TTP_XOR_QUAD_CurrentVersionRun_13fa {
  strings:
    $key_13fa = { 40 95 [2] 64 9b [2] 4f b7 [2] 61 95 [2] 75 8e [2] 7a 94 [2] 64 89 [2] 66 88 [2] 7d 8e [2] 61 89 [2] 7d a6 }

  condition:
    any of them
}