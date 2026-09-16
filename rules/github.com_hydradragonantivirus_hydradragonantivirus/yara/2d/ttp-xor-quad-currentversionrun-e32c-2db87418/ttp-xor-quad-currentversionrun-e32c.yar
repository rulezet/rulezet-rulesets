rule TTP_XOR_QUAD_CurrentVersionRun_e32c {
  strings:
    $key_e32c = { b0 43 [2] 94 4d [2] bf 61 [2] 91 43 [2] 85 58 [2] 8a 42 [2] 94 5f [2] 96 5e [2] 8d 58 [2] 91 5f [2] 8d 70 }

  condition:
    any of them
}