rule TTP_XOR_QUAD_CurrentVersionRun_e83c {
  strings:
    $key_e83c = { bb 53 [2] 9f 5d [2] b4 71 [2] 9a 53 [2] 8e 48 [2] 81 52 [2] 9f 4f [2] 9d 4e [2] 86 48 [2] 9a 4f [2] 86 60 }

  condition:
    any of them
}