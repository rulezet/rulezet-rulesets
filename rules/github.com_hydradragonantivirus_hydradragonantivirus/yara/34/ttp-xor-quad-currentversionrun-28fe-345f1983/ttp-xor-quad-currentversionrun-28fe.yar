rule TTP_XOR_QUAD_CurrentVersionRun_28fe {
  strings:
    $key_28fe = { 7b 91 [2] 5f 9f [2] 74 b3 [2] 5a 91 [2] 4e 8a [2] 41 90 [2] 5f 8d [2] 5d 8c [2] 46 8a [2] 5a 8d [2] 46 a2 }

  condition:
    any of them
}