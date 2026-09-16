rule TTP_XOR_QUAD_CurrentVersionRun_39fe {
  strings:
    $key_39fe = { 6a 91 [2] 4e 9f [2] 65 b3 [2] 4b 91 [2] 5f 8a [2] 50 90 [2] 4e 8d [2] 4c 8c [2] 57 8a [2] 4b 8d [2] 57 a2 }

  condition:
    any of them
}