rule TTP_XOR_QUAD_CurrentVersionRun_f37c {
  strings:
    $key_f37c = { a0 13 [2] 84 1d [2] af 31 [2] 81 13 [2] 95 08 [2] 9a 12 [2] 84 0f [2] 86 0e [2] 9d 08 [2] 81 0f [2] 9d 20 }

  condition:
    any of them
}