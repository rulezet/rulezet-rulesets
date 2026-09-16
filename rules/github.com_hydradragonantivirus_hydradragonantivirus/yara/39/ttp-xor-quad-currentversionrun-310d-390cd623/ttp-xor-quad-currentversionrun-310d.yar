rule TTP_XOR_QUAD_CurrentVersionRun_310d {
  strings:
    $key_310d = { 62 62 [2] 46 6c [2] 6d 40 [2] 43 62 [2] 57 79 [2] 58 63 [2] 46 7e [2] 44 7f [2] 5f 79 [2] 43 7e [2] 5f 51 }

  condition:
    any of them
}