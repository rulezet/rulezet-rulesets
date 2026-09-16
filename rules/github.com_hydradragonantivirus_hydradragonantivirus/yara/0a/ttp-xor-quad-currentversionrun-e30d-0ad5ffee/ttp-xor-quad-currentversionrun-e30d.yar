rule TTP_XOR_QUAD_CurrentVersionRun_e30d {
  strings:
    $key_e30d = { b0 62 [2] 94 6c [2] bf 40 [2] 91 62 [2] 85 79 [2] 8a 63 [2] 94 7e [2] 96 7f [2] 8d 79 [2] 91 7e [2] 8d 51 }

  condition:
    any of them
}