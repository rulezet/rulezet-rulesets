rule TTP_XOR_QUAD_CurrentVersionRun_f10c {
  strings:
    $key_f10c = { a2 63 [2] 86 6d [2] ad 41 [2] 83 63 [2] 97 78 [2] 98 62 [2] 86 7f [2] 84 7e [2] 9f 78 [2] 83 7f [2] 9f 50 }

  condition:
    any of them
}