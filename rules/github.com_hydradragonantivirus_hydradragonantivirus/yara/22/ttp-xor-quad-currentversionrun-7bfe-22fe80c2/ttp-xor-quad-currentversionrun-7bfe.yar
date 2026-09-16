rule TTP_XOR_QUAD_CurrentVersionRun_7bfe {
  strings:
    $key_7bfe = { 28 91 [2] 0c 9f [2] 27 b3 [2] 09 91 [2] 1d 8a [2] 12 90 [2] 0c 8d [2] 0e 8c [2] 15 8a [2] 09 8d [2] 15 a2 }

  condition:
    any of them
}