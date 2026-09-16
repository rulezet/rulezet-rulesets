rule TTP_XOR_QUAD_CurrentVersionRun_e34f {
  strings:
    $key_e34f = { b0 20 [2] 94 2e [2] bf 02 [2] 91 20 [2] 85 3b [2] 8a 21 [2] 94 3c [2] 96 3d [2] 8d 3b [2] 91 3c [2] 8d 13 }

  condition:
    any of them
}