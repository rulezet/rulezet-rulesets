rule TTP_XOR_QUAD_CurrentVersionRun_48fe {
  strings:
    $key_48fe = { 1b 91 [2] 3f 9f [2] 14 b3 [2] 3a 91 [2] 2e 8a [2] 21 90 [2] 3f 8d [2] 3d 8c [2] 26 8a [2] 3a 8d [2] 26 a2 }

  condition:
    any of them
}