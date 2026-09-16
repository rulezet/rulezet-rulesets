rule TTP_XOR_QUAD_CurrentVersionRun_68fe {
  strings:
    $key_68fe = { 3b 91 [2] 1f 9f [2] 34 b3 [2] 1a 91 [2] 0e 8a [2] 01 90 [2] 1f 8d [2] 1d 8c [2] 06 8a [2] 1a 8d [2] 06 a2 }

  condition:
    any of them
}