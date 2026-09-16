rule TTP_XOR_QUAD_CurrentVersionRun_49ff {
  strings:
    $key_49ff = { 1a 90 [2] 3e 9e [2] 15 b2 [2] 3b 90 [2] 2f 8b [2] 20 91 [2] 3e 8c [2] 3c 8d [2] 27 8b [2] 3b 8c [2] 27 a3 }

  condition:
    any of them
}