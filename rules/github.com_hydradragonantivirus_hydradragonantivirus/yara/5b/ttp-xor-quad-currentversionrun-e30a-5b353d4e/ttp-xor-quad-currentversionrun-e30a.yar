rule TTP_XOR_QUAD_CurrentVersionRun_e30a {
  strings:
    $key_e30a = { b0 65 [2] 94 6b [2] bf 47 [2] 91 65 [2] 85 7e [2] 8a 64 [2] 94 79 [2] 96 78 [2] 8d 7e [2] 91 79 [2] 8d 56 }

  condition:
    any of them
}