rule TTP_XOR_QUAD_CurrentVersionRun_f10d {
  strings:
    $key_f10d = { a2 62 [2] 86 6c [2] ad 40 [2] 83 62 [2] 97 79 [2] 98 63 [2] 86 7e [2] 84 7f [2] 9f 79 [2] 83 7e [2] 9f 51 }

  condition:
    any of them
}