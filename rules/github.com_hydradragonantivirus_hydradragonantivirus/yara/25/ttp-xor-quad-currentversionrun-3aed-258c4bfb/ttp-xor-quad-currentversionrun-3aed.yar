rule TTP_XOR_QUAD_CurrentVersionRun_3aed {
  strings:
    $key_3aed = { 69 82 [2] 4d 8c [2] 66 a0 [2] 48 82 [2] 5c 99 [2] 53 83 [2] 4d 9e [2] 4f 9f [2] 54 99 [2] 48 9e [2] 54 b1 }

  condition:
    any of them
}