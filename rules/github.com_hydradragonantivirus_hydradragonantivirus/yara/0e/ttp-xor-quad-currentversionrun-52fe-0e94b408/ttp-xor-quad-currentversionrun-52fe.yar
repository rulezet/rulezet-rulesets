rule TTP_XOR_QUAD_CurrentVersionRun_52fe {
  strings:
    $key_52fe = { 01 91 [2] 25 9f [2] 0e b3 [2] 20 91 [2] 34 8a [2] 3b 90 [2] 25 8d [2] 27 8c [2] 3c 8a [2] 20 8d [2] 3c a2 }

  condition:
    any of them
}