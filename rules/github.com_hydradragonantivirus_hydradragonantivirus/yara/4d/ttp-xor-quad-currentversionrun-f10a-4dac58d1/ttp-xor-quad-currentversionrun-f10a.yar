rule TTP_XOR_QUAD_CurrentVersionRun_f10a {
  strings:
    $key_f10a = { a2 65 [2] 86 6b [2] ad 47 [2] 83 65 [2] 97 7e [2] 98 64 [2] 86 79 [2] 84 78 [2] 9f 7e [2] 83 79 [2] 9f 56 }

  condition:
    any of them
}