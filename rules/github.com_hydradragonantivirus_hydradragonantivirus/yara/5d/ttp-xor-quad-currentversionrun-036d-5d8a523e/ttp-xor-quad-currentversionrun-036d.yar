rule TTP_XOR_QUAD_CurrentVersionRun_036d {
  strings:
    $key_036d = { 50 02 [2] 74 0c [2] 5f 20 [2] 71 02 [2] 65 19 [2] 6a 03 [2] 74 1e [2] 76 1f [2] 6d 19 [2] 71 1e [2] 6d 31 }

  condition:
    any of them
}