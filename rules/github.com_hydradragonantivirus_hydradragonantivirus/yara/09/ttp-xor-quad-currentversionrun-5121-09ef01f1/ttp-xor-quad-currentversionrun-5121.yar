rule TTP_XOR_QUAD_CurrentVersionRun_5121 {
  strings:
    $key_5121 = { 02 4e [2] 26 40 [2] 0d 6c [2] 23 4e [2] 37 55 [2] 38 4f [2] 26 52 [2] 24 53 [2] 3f 55 [2] 23 52 [2] 3f 7d }

  condition:
    any of them
}