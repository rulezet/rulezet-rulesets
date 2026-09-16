rule TTP_XOR_QUAD_CurrentVersionRun_e300 {
  strings:
    $key_e300 = { b0 6f [2] 94 61 [2] bf 4d [2] 91 6f [2] 85 74 [2] 8a 6e [2] 94 73 [2] 96 72 [2] 8d 74 [2] 91 73 [2] 8d 5c }

  condition:
    any of them
}