rule TTP_XOR_QUAD_CurrentVersionRun_e310 {
  strings:
    $key_e310 = { b0 7f [2] 94 71 [2] bf 5d [2] 91 7f [2] 85 64 [2] 8a 7e [2] 94 63 [2] 96 62 [2] 8d 64 [2] 91 63 [2] 8d 4c }

  condition:
    any of them
}