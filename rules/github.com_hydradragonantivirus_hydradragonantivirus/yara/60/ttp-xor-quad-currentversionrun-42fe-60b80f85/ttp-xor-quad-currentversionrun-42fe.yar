rule TTP_XOR_QUAD_CurrentVersionRun_42fe {
  strings:
    $key_42fe = { 11 91 [2] 35 9f [2] 1e b3 [2] 30 91 [2] 24 8a [2] 2b 90 [2] 35 8d [2] 37 8c [2] 2c 8a [2] 30 8d [2] 2c a2 }

  condition:
    any of them
}