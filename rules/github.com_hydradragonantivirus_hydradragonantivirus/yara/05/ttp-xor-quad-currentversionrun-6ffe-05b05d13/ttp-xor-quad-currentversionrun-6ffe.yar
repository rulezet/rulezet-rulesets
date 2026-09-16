rule TTP_XOR_QUAD_CurrentVersionRun_6ffe {
  strings:
    $key_6ffe = { 3c 91 [2] 18 9f [2] 33 b3 [2] 1d 91 [2] 09 8a [2] 06 90 [2] 18 8d [2] 1a 8c [2] 01 8a [2] 1d 8d [2] 01 a2 }

  condition:
    any of them
}