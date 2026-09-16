rule TTP_XOR_QUAD_CurrentVersionRun_f7ff {
  strings:
    $key_f7ff = { a4 90 [2] 80 9e [2] ab b2 [2] 85 90 [2] 91 8b [2] 9e 91 [2] 80 8c [2] 82 8d [2] 99 8b [2] 85 8c [2] 99 a3 }

  condition:
    any of them
}