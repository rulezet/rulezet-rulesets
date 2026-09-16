rule TTP_XOR_QUAD_CurrentVersionRun_5ffe {
  strings:
    $key_5ffe = { 0c 91 [2] 28 9f [2] 03 b3 [2] 2d 91 [2] 39 8a [2] 36 90 [2] 28 8d [2] 2a 8c [2] 31 8a [2] 2d 8d [2] 31 a2 }

  condition:
    any of them
}