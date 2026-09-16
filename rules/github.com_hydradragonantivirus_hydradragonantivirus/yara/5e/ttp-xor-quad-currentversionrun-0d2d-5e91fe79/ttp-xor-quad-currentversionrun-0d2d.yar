rule TTP_XOR_QUAD_CurrentVersionRun_0d2d {
  strings:
    $key_0d2d = { 5e 42 [2] 7a 4c [2] 51 60 [2] 7f 42 [2] 6b 59 [2] 64 43 [2] 7a 5e [2] 78 5f [2] 63 59 [2] 7f 5e [2] 63 71 }

  condition:
    any of them
}