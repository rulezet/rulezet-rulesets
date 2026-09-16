rule TTP_XOR_QUAD_CurrentVersionRun_e871 {
  strings:
    $key_e871 = { bb 1e [2] 9f 10 [2] b4 3c [2] 9a 1e [2] 8e 05 [2] 81 1f [2] 9f 02 [2] 9d 03 [2] 86 05 [2] 9a 02 [2] 86 2d }

  condition:
    any of them
}