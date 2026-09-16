rule TTP_XOR_QUAD_CurrentVersionRun_08fe {
  strings:
    $key_08fe = { 5b 91 [2] 7f 9f [2] 54 b3 [2] 7a 91 [2] 6e 8a [2] 61 90 [2] 7f 8d [2] 7d 8c [2] 66 8a [2] 7a 8d [2] 66 a2 }

  condition:
    any of them
}