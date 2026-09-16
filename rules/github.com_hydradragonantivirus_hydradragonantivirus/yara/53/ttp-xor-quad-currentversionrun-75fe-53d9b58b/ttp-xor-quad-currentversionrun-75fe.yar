rule TTP_XOR_QUAD_CurrentVersionRun_75fe {
  strings:
    $key_75fe = { 26 91 [2] 02 9f [2] 29 b3 [2] 07 91 [2] 13 8a [2] 1c 90 [2] 02 8d [2] 00 8c [2] 1b 8a [2] 07 8d [2] 1b a2 }

  condition:
    any of them
}