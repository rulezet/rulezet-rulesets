rule TTP_XOR_QUAD_CurrentVersionRun_9afe {
  strings:
    $key_9afe = { c9 91 [2] ed 9f [2] c6 b3 [2] e8 91 [2] fc 8a [2] f3 90 [2] ed 8d [2] ef 8c [2] f4 8a [2] e8 8d [2] f4 a2 }

  condition:
    any of them
}