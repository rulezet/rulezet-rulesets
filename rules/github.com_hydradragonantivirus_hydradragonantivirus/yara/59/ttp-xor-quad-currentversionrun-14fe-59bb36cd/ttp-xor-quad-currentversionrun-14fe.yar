rule TTP_XOR_QUAD_CurrentVersionRun_14fe {
  strings:
    $key_14fe = { 47 91 [2] 63 9f [2] 48 b3 [2] 66 91 [2] 72 8a [2] 7d 90 [2] 63 8d [2] 61 8c [2] 7a 8a [2] 66 8d [2] 7a a2 }

  condition:
    any of them
}