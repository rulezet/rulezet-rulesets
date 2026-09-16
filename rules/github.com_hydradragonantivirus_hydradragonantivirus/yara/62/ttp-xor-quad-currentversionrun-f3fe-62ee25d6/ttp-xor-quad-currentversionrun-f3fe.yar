rule TTP_XOR_QUAD_CurrentVersionRun_f3fe {
  strings:
    $key_f3fe = { a0 91 [2] 84 9f [2] af b3 [2] 81 91 [2] 95 8a [2] 9a 90 [2] 84 8d [2] 86 8c [2] 9d 8a [2] 81 8d [2] 9d a2 }

  condition:
    any of them
}