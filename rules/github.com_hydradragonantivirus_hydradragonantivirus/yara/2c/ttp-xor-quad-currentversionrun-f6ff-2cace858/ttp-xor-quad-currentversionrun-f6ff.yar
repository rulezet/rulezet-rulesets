rule TTP_XOR_QUAD_CurrentVersionRun_f6ff {
  strings:
    $key_f6ff = { a5 90 [2] 81 9e [2] aa b2 [2] 84 90 [2] 90 8b [2] 9f 91 [2] 81 8c [2] 83 8d [2] 98 8b [2] 84 8c [2] 98 a3 }

  condition:
    any of them
}