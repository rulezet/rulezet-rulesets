rule TTP_XOR_QUAD_CurrentVersionRun_31fe {
  strings:
    $key_31fe = { 62 91 [2] 46 9f [2] 6d b3 [2] 43 91 [2] 57 8a [2] 58 90 [2] 46 8d [2] 44 8c [2] 5f 8a [2] 43 8d [2] 5f a2 }

  condition:
    any of them
}