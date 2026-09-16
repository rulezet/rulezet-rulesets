rule TTP_XOR_QUAD_CurrentVersionRun_117d {
  strings:
    $key_117d = { 42 12 [2] 66 1c [2] 4d 30 [2] 63 12 [2] 77 09 [2] 78 13 [2] 66 0e [2] 64 0f [2] 7f 09 [2] 63 0e [2] 7f 21 }

  condition:
    any of them
}