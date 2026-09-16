rule TTP_XOR_QUAD_CurrentVersionRun_f1ff {
  strings:
    $key_f1ff = { a2 90 [2] 86 9e [2] ad b2 [2] 83 90 [2] 97 8b [2] 98 91 [2] 86 8c [2] 84 8d [2] 9f 8b [2] 83 8c [2] 9f a3 }

  condition:
    any of them
}