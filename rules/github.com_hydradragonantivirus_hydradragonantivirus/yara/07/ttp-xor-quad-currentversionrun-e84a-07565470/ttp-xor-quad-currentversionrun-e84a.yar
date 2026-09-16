rule TTP_XOR_QUAD_CurrentVersionRun_e84a {
  strings:
    $key_e84a = { bb 25 [2] 9f 2b [2] b4 07 [2] 9a 25 [2] 8e 3e [2] 81 24 [2] 9f 39 [2] 9d 38 [2] 86 3e [2] 9a 39 [2] 86 16 }

  condition:
    any of them
}