rule TTP_XOR_QUAD_CurrentVersionRun_57ff {
  strings:
    $key_57ff = { 04 90 [2] 20 9e [2] 0b b2 [2] 25 90 [2] 31 8b [2] 3e 91 [2] 20 8c [2] 22 8d [2] 39 8b [2] 25 8c [2] 39 a3 }

  condition:
    any of them
}