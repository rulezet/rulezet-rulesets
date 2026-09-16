rule TTP_XOR_QUAD_CurrentVersionRun_f65c {
  strings:
    $key_f65c = { a5 33 [2] 81 3d [2] aa 11 [2] 84 33 [2] 90 28 [2] 9f 32 [2] 81 2f [2] 83 2e [2] 98 28 [2] 84 2f [2] 98 00 }

  condition:
    any of them
}