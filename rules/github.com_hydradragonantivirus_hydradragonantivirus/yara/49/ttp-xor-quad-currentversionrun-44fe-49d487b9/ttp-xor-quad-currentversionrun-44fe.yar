rule TTP_XOR_QUAD_CurrentVersionRun_44fe {
  strings:
    $key_44fe = { 17 91 [2] 33 9f [2] 18 b3 [2] 36 91 [2] 22 8a [2] 2d 90 [2] 33 8d [2] 31 8c [2] 2a 8a [2] 36 8d [2] 2a a2 }

  condition:
    any of them
}