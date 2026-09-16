rule TTP_XOR_QUAD_CurrentVersionRun_106a {
  strings:
    $key_106a = { 43 05 [2] 67 0b [2] 4c 27 [2] 62 05 [2] 76 1e [2] 79 04 [2] 67 19 [2] 65 18 [2] 7e 1e [2] 62 19 [2] 7e 36 }

  condition:
    any of them
}