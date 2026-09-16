rule TTP_XOR_QUAD_CurrentVersionRun_11fe {
  strings:
    $key_11fe = { 42 91 [2] 66 9f [2] 4d b3 [2] 63 91 [2] 77 8a [2] 78 90 [2] 66 8d [2] 64 8c [2] 7f 8a [2] 63 8d [2] 7f a2 }

  condition:
    any of them
}