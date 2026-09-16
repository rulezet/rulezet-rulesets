rule TTP_XOR_QUAD_CurrentVersionRun_7ffe {
  strings:
    $key_7ffe = { 2c 91 [2] 08 9f [2] 23 b3 [2] 0d 91 [2] 19 8a [2] 16 90 [2] 08 8d [2] 0a 8c [2] 11 8a [2] 0d 8d [2] 11 a2 }

  condition:
    any of them
}