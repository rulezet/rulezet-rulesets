rule TTP_XOR_QUAD_CurrentVersionRun_e653 {
  strings:
    $key_e653 = { b5 3c [2] 91 32 [2] ba 1e [2] 94 3c [2] 80 27 [2] 8f 3d [2] 91 20 [2] 93 21 [2] 88 27 [2] 94 20 [2] 88 0f }

  condition:
    any of them
}