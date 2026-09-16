rule TTP_XOR_QUAD_CurrentVersionRun_6a2a {
  strings:
    $key_6a2a = { 39 45 [2] 1d 4b [2] 36 67 [2] 18 45 [2] 0c 5e [2] 03 44 [2] 1d 59 [2] 1f 58 [2] 04 5e [2] 18 59 [2] 04 76 }

  condition:
    any of them
}