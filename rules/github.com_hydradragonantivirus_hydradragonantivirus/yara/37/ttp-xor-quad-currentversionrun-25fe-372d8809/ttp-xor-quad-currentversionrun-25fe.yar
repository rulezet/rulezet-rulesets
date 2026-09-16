rule TTP_XOR_QUAD_CurrentVersionRun_25fe {
  strings:
    $key_25fe = { 76 91 [2] 52 9f [2] 79 b3 [2] 57 91 [2] 43 8a [2] 4c 90 [2] 52 8d [2] 50 8c [2] 4b 8a [2] 57 8d [2] 4b a2 }

  condition:
    any of them
}