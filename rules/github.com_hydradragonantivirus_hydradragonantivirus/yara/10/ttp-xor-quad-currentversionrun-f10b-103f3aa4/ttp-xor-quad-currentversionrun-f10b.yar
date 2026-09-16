rule TTP_XOR_QUAD_CurrentVersionRun_f10b {
  strings:
    $key_f10b = { a2 64 [2] 86 6a [2] ad 46 [2] 83 64 [2] 97 7f [2] 98 65 [2] 86 78 [2] 84 79 [2] 9f 7f [2] 83 78 [2] 9f 57 }

  condition:
    any of them
}