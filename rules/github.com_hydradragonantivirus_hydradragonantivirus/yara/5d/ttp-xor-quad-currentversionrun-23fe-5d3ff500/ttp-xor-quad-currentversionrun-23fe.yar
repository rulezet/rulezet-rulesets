rule TTP_XOR_QUAD_CurrentVersionRun_23fe {
  strings:
    $key_23fe = { 70 91 [2] 54 9f [2] 7f b3 [2] 51 91 [2] 45 8a [2] 4a 90 [2] 54 8d [2] 56 8c [2] 4d 8a [2] 51 8d [2] 4d a2 }

  condition:
    any of them
}