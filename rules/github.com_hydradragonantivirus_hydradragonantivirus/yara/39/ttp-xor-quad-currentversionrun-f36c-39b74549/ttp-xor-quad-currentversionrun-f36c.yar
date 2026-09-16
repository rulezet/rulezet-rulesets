rule TTP_XOR_QUAD_CurrentVersionRun_f36c {
  strings:
    $key_f36c = { a0 03 [2] 84 0d [2] af 21 [2] 81 03 [2] 95 18 [2] 9a 02 [2] 84 1f [2] 86 1e [2] 9d 18 [2] 81 1f [2] 9d 30 }

  condition:
    any of them
}