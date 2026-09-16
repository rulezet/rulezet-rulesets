rule TTP_XOR_QUAD_CurrentVersionRun_1afe {
  strings:
    $key_1afe = { 49 91 [2] 6d 9f [2] 46 b3 [2] 68 91 [2] 7c 8a [2] 73 90 [2] 6d 8d [2] 6f 8c [2] 74 8a [2] 68 8d [2] 74 a2 }

  condition:
    any of them
}