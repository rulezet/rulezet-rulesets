rule TTP_XOR_QUAD_CurrentVersionRun_4ffe {
  strings:
    $key_4ffe = { 1c 91 [2] 38 9f [2] 13 b3 [2] 3d 91 [2] 29 8a [2] 26 90 [2] 38 8d [2] 3a 8c [2] 21 8a [2] 3d 8d [2] 21 a2 }

  condition:
    any of them
}