rule TTP_XOR_QUAD_CurrentVersionRun_f12e {
  strings:
    $key_f12e = { a2 41 [2] 86 4f [2] ad 63 [2] 83 41 [2] 97 5a [2] 98 40 [2] 86 5d [2] 84 5c [2] 9f 5a [2] 83 5d [2] 9f 72 }

  condition:
    any of them
}