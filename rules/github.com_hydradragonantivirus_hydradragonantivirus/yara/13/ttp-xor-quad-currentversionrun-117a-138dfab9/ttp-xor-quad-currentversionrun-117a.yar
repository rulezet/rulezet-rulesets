rule TTP_XOR_QUAD_CurrentVersionRun_117a {
  strings:
    $key_117a = { 42 15 [2] 66 1b [2] 4d 37 [2] 63 15 [2] 77 0e [2] 78 14 [2] 66 09 [2] 64 08 [2] 7f 0e [2] 63 09 [2] 7f 26 }

  condition:
    any of them
}