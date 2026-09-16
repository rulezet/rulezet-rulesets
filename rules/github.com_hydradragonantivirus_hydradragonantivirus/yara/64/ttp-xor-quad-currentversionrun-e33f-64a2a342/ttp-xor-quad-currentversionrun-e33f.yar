rule TTP_XOR_QUAD_CurrentVersionRun_e33f {
  strings:
    $key_e33f = { b0 50 [2] 94 5e [2] bf 72 [2] 91 50 [2] 85 4b [2] 8a 51 [2] 94 4c [2] 96 4d [2] 8d 4b [2] 91 4c [2] 8d 63 }

  condition:
    any of them
}