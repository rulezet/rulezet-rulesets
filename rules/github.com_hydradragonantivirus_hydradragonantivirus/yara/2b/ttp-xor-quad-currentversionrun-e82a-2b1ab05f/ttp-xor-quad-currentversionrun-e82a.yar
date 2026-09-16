rule TTP_XOR_QUAD_CurrentVersionRun_e82a {
  strings:
    $key_e82a = { bb 45 [2] 9f 4b [2] b4 67 [2] 9a 45 [2] 8e 5e [2] 81 44 [2] 9f 59 [2] 9d 58 [2] 86 5e [2] 9a 59 [2] 86 76 }

  condition:
    any of them
}