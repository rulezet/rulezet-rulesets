rule TTP_XOR_QUAD_CurrentVersionRun_f11c {
  strings:
    $key_f11c = { a2 73 [2] 86 7d [2] ad 51 [2] 83 73 [2] 97 68 [2] 98 72 [2] 86 6f [2] 84 6e [2] 9f 68 [2] 83 6f [2] 9f 40 }

  condition:
    any of them
}