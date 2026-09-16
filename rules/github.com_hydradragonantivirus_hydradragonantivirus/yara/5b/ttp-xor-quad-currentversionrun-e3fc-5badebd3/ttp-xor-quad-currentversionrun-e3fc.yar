rule TTP_XOR_QUAD_CurrentVersionRun_e3fc {
  strings:
    $key_e3fc = { b0 93 [2] 94 9d [2] bf b1 [2] 91 93 [2] 85 88 [2] 8a 92 [2] 94 8f [2] 96 8e [2] 8d 88 [2] 91 8f [2] 8d a0 }

  condition:
    any of them
}