rule TTP_XOR_QUAD_CurrentVersionRun_3e0d {
  strings:
    $key_3e0d = { 6d 62 [2] 49 6c [2] 62 40 [2] 4c 62 [2] 58 79 [2] 57 63 [2] 49 7e [2] 4b 7f [2] 50 79 [2] 4c 7e [2] 50 51 }

  condition:
    any of them
}