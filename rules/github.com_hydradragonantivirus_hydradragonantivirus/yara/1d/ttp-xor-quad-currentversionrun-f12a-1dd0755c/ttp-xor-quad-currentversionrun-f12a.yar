rule TTP_XOR_QUAD_CurrentVersionRun_f12a {
  strings:
    $key_f12a = { a2 45 [2] 86 4b [2] ad 67 [2] 83 45 [2] 97 5e [2] 98 44 [2] 86 59 [2] 84 58 [2] 9f 5e [2] 83 59 [2] 9f 76 }

  condition:
    any of them
}